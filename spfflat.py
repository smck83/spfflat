#!/usr/bin/env python3
"""
SPF Flattener Container
=======================
Reads a source SPF record from {SOURCE_ID}._source.{domain},
resolves all includes/redirects/a/mx into ip4/ip6 entries,
and publishes flattened chained TXT records at {SOURCE_ID}.{domain}.

Supports: Cloudflare, Route53, Bunny.net DNS
Alerts:   Email (SMTP), Slack, Telegram, MS Teams (all optional)

All configuration via environment variables.
"""

import os
import sys
import time
import hashlib
import logging
import json
import re
import signal
import traceback
from typing import Optional
from ipaddress import ip_network, IPv4Network, IPv6Network

import dns.resolver
import dns.exception
import requests
from functools import wraps

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("spfflat")

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_shutdown = False

def _handle_signal(signum, frame):
    global _shutdown
    log.info("Received signal %s, shutting down after current cycle…", signum)
    _shutdown = True

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
SOURCE_ID     = os.environ.get("SOURCE_ID", "qazwsx3")
MY_DOMAINS    = os.environ.get("MY_DOMAINS", "").split()
SCHEDULE      = int(os.environ.get("SCHEDULE", "60"))        # minutes
DNS_PROVIDER  = os.environ.get("DNS_PROVIDER", "cloudflare") # cloudflare | route53 | bunny
DNS_TTL       = int(os.environ.get("DNS_TTL", "300"))
RESOLVERS     = os.environ.get("RESOLVERS", "1.1.1.1,8.8.8.8").split(",")
SPF_ALL_QUAL  = os.environ.get("SPF_ALL_QUALIFIER", "")      # override ~all / -all etc. empty = use source
MAX_TXT_LEN   = int(os.environ.get("MAX_TXT_LEN", "450"))
# MAX_TXT_LEN note: the DNS spec limits each TXT *string* to 255 bytes, but a
# single TXT record may contain multiple strings concatenated by the resolver.
# Most managed DNS providers handle the multi-string encoding automatically, so
# 450 is a safe conservative limit for the *logical* value we write. If your
# provider enforces a strict single-string limit, lower this to 253.
DRY_RUN       = os.environ.get("DRY_RUN", "false").lower() in ("true", "1", "yes")
RUN_ONCE      = os.environ.get("RUN_ONCE", "false").lower() in ("true", "1", "yes")

# Cloudflare
CF_API_TOKEN  = os.environ.get("CF_API_TOKEN", "")
CF_API_KEY    = os.environ.get("CF_API_KEY", "")
CF_API_EMAIL  = os.environ.get("CF_API_EMAIL", "")

# Route53
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION            = os.environ.get("AWS_REGION", "us-east-1")

# Bunny.net
BUNNY_API_KEY = os.environ.get("BUNNY_API_KEY", "")

# Alerting - SMTP
SMTP_HOST     = os.environ.get("SMTP_HOST", "")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", "")
SMTP_PASS     = os.environ.get("SMTP_PASS", "")
SMTP_FROM     = os.environ.get("SMTP_FROM", "")
SMTP_TO       = os.environ.get("SMTP_TO", "")        # comma-separated
SMTP_TLS      = os.environ.get("SMTP_TLS", "true").lower() in ("true", "1", "yes")

# Alerting - Slack
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# Alerting - Telegram
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")

# Alerting - MS Teams
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")

# Alerting - Discord
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# ---------------------------------------------------------------------------
# DNS Resolver
# ---------------------------------------------------------------------------
def get_resolver():
    r = dns.resolver.Resolver()
    r.nameservers = [s.strip() for s in RESOLVERS if s.strip()]
    r.lifetime = 10
    return r

RESOLVER = get_resolver()

# ===========================================================================
# RETRY HELPER
# ===========================================================================

def _with_retry(fn, *args, retries=3, backoff=2.0, label='operation', **kwargs):
    # Retry fn up to `retries` times with exponential backoff.
    for attempt in range(1, retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if attempt == retries:
                log.error('%s failed after %d attempts: %s', label, retries, exc)
                raise
            wait = backoff ** (attempt - 1)
            log.warning('%s attempt %d/%d failed (%s) -- retrying in %.1fs',
                        label, attempt, retries, exc, wait)
            time.sleep(wait)


def _http(method, url, label, **kwargs):
    # Thin retry wrapper around requests. Treats 429 as a retriable error.
    def _do():
        resp = requests.request(method, url, timeout=15, **kwargs)
        if resp.status_code == 429:
            raise IOError('429 Too Many Requests')
        return resp
    return _with_retry(_do, label=label)


# ===========================================================================
# SPF RESOLUTION ENGINE
# ===========================================================================

def query_txt(domain: str) -> list[str]:
    """Return all TXT record strings for a domain."""
    try:
        answers = _with_retry(RESOLVER.resolve, domain, "TXT", label=f"TXT {domain}")
        results = []
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            results.append(txt)
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        log.warning("DNS timeout querying TXT for %s", domain)
        return []

def query_a(domain: str) -> list[str]:
    try:
        return [str(r) for r in _with_retry(RESOLVER.resolve, domain, "A", label=f"A {domain}")]
    except Exception:
        return []

def query_aaaa(domain: str) -> list[str]:
    try:
        return [str(r) for r in _with_retry(RESOLVER.resolve, domain, "AAAA", label=f"AAAA {domain}")]
    except Exception:
        return []

def query_mx(domain: str) -> list[str]:
    """Resolve MX -> A/AAAA."""
    ips = []
    try:
        for rdata in RESOLVER.resolve(domain, "MX"):
            mx_host = str(rdata.exchange).rstrip(".")
            ips.extend(query_a(mx_host))
            ips.extend(query_aaaa(mx_host))
    except Exception:
        pass
    return ips

def resolve_spf(domain: str, depth: int = 0, seen: set | None = None) -> tuple[set, str]:
    """
    Recursively resolve an SPF record into a set of ip4:/ip6: mechanisms.
    Returns (set_of_ip_mechanisms, all_qualifier).
    """
    if seen is None:
        seen = set()
    if domain in seen or depth > 15:
        return set(), "~all"
    seen.add(domain)

    ips = set()
    all_qual = "~all"

    txts = query_txt(domain)
    spf_record = None
    for txt in txts:
        if txt.startswith("v=spf1 ") or txt == "v=spf1":
            spf_record = txt
            break

    if not spf_record:
        return ips, all_qual

    parts = spf_record.split()
    for part in parts[1:]:  # skip v=spf1
        p = part.lower().strip()

        # all qualifier
        if p in ("-all", "~all", "+all", "?all"):
            all_qual = p
            continue

        # ip4 / ip6 direct
        if p.startswith("ip4:") or p.startswith("ip6:"):
            addr = part[4:]  # preserve original case for IPv6
            if "/" not in addr:
                addr += "/32" if p.startswith("ip4:") else "/128"
            try:
                ip_network(addr, strict=False)
                prefix = "ip4:" if p.startswith("ip4:") else "ip6:"
                ips.add(prefix + addr)
            except ValueError:
                log.warning("Invalid IP in SPF for %s: %s", domain, part)
            continue

        # include
        if p.startswith("include:"):
            inc_domain = p[8:]
            # Per RFC 7208 s5.2: the `all` mechanism from an included record
            # is deliberately ignored — only its IP mechanisms are inherited.
            child_ips, _ = resolve_spf(inc_domain, depth + 1, seen)
            ips.update(child_ips)
            continue

        # redirect
        if p.startswith("redirect="):
            redir_domain = p[9:]
            child_ips, child_all = resolve_spf(redir_domain, depth + 1, seen)
            ips.update(child_ips)
            all_qual = child_all
            continue

        # a mechanism
        if p == "a" or p.startswith("a:") or p.startswith("a/"):
            if p == "a":
                target = domain
            elif p.startswith("a:"):
                target = p[2:].split("/")[0]
            else:
                target = domain
            for ip in query_a(target):
                ips.add(f"ip4:{ip}/32")
            for ip in query_aaaa(target):
                ips.add(f"ip6:{ip}/128")
            continue

        # mx mechanism
        if p == "mx" or p.startswith("mx:") or p.startswith("mx/"):
            if p.startswith("mx:"):
                target = p[3:].split("/")[0]
            else:
                target = domain
            for ip in query_mx(target):
                try:
                    net = ip_network(ip, strict=False)
                    if isinstance(net, IPv4Network):
                        ips.add(f"ip4:{ip}/32")
                    else:
                        ips.add(f"ip6:{ip}/128")
                except ValueError:
                    pass
            continue

        # exists, ptr, exp — skip (exists doesn't produce IPs, ptr is deprecated)
        if p.startswith("exists:") or p.startswith("ptr") or p.startswith("exp="):
            continue

    return ips, all_qual


def build_spf_records(ip_mechanisms: set, all_qualifier: str, source_id: str, domain: str) -> dict[str, str]:
    """
    Build chained SPF TXT records that fit within MAX_TXT_LEN each.
    Returns {fqdn: txt_value} e.g.:
      qazwsx3.example.com -> "v=spf1 ip4:... include:qazwsx3_1.example.com ~all"
      qazwsx3_1.example.com -> "v=spf1 ip4:... ~all"
    """
    sorted_mechs = sorted(ip_mechanisms)

    # Split into chunks that fit
    chunks: list[list[str]] = []
    current: list[str] = []
    current_len = len("v=spf1 ") + len(f" include:{source_id}_X.{domain}") + len(f" {all_qualifier}")

    for mech in sorted_mechs:
        needed = len(mech) + 1  # space + mechanism
        if current_len + needed > MAX_TXT_LEN and current:
            chunks.append(current)
            current = []
            current_len = len("v=spf1 ") + len(f" include:{source_id}_X.{domain}") + len(f" {all_qualifier}")
        current.append(mech)
        current_len += needed

    if current:
        chunks.append(current)

    if not chunks:
        chunks = [[]]  # at least one record with just the all qualifier

    records = {}
    for i, chunk in enumerate(chunks):
        if i == 0:
            name = f"{source_id}.{domain}"
        else:
            name = f"{source_id}_{i}.{domain}"

        mechs_str = " ".join(chunk)
        if i < len(chunks) - 1:
            next_name = f"{source_id}_{i + 1}.{domain}"
            txt = f"v=spf1 {mechs_str} include:{next_name} {all_qualifier}".strip()
        else:
            txt = f"v=spf1 {mechs_str} {all_qualifier}".strip()

        # Clean up double spaces
        txt = re.sub(r"\s+", " ", txt)
        records[name] = txt

    return records


# ===========================================================================
# STATE MANAGEMENT VIA DNS (_state. records)
# ===========================================================================

def compute_hash(records: dict[str, str]) -> str:
    """Compute a deterministic hash of the flattened records."""
    canonical = json.dumps(records, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]

def get_state_hash(domain: str) -> str:
    """Read hash from {SOURCE_ID}._state.{domain} TXT record."""
    state_name = f"{SOURCE_ID}._state.{domain}"
    txts = query_txt(state_name)
    for txt in txts:
        if txt.startswith("spfflat_hash="):
            return txt.split("=", 1)[1]
    return ""

# ===========================================================================
# DNS PROVIDER ABSTRACTION
# ===========================================================================

class DNSProvider:
    """Base class for DNS providers."""

    def get_zone_id(self, domain: str) -> Optional[str]:
        raise NotImplementedError

    def list_txt_records(self, zone_id: str, domain: str) -> list[dict]:
        """Return list of {id, name, value} for TXT records in zone."""
        raise NotImplementedError

    def create_txt_record(self, zone_id: str, name: str, value: str, domain: str):
        raise NotImplementedError

    def update_txt_record(self, zone_id: str, record_id: str, name: str, value: str, domain: str):
        raise NotImplementedError

    def delete_txt_record(self, zone_id: str, record_id: str, domain: str):
        raise NotImplementedError

    def upsert_txt(self, zone_id: str, fqdn: str, value: str, domain: str, existing: list[dict]):
        """Create or update a TXT record."""
        # fqdn = "qazwsx3.example.com", we need relative name for some providers
        for rec in existing:
            if rec["name"].rstrip(".").lower() == fqdn.rstrip(".").lower():
                if rec["value"] != value:
                    log.info("  UPDATE %s", fqdn)
                    self.update_txt_record(zone_id, rec["id"], fqdn, value, domain)
                else:
                    log.debug("  UNCHANGED %s", fqdn)
                return
        log.info("  CREATE %s", fqdn)
        self.create_txt_record(zone_id, fqdn, value, domain)

    def sync_records(self, zone_id: str, desired: dict[str, str], domain: str):
        """
        Sync desired {fqdn: value} to DNS.
        Creates/updates desired records and deletes orphans under SOURCE_ID namespace.
        """
        existing = self.list_txt_records(zone_id, domain)

        # Filter existing to only records we manage (SOURCE_ID prefix)
        managed_prefix = f"{SOURCE_ID}".lower()
        state_name = f"{SOURCE_ID}._state.{domain}".lower()
        source_name = f"{SOURCE_ID}._source.{domain}".lower()

        managed_existing = [
            r for r in existing
            if r["name"].rstrip(".").lower().startswith(managed_prefix)
            and r["name"].rstrip(".").lower() != source_name
        ]

        # Upsert desired records
        for fqdn, value in desired.items():
            if DRY_RUN:
                log.info("  [DRY RUN] Would upsert %s = %s", fqdn, value[:80])
            else:
                self.upsert_txt(zone_id, fqdn, value, domain, managed_existing)

        # Delete orphans (managed records not in desired and not _state)
        desired_names = {k.rstrip(".").lower() for k in desired}
        for rec in managed_existing:
            rname = rec["name"].rstrip(".").lower()
            if rname not in desired_names and rname != state_name:
                log.info("  DELETE orphan %s", rec["name"])
                if not DRY_RUN:
                    self.delete_txt_record(zone_id, rec["id"], domain)


# ---------------------------------------------------------------------------
# Cloudflare Provider
# ---------------------------------------------------------------------------
class CloudflareProvider(DNSProvider):
    BASE = "https://api.cloudflare.com/client/v4"

    def _headers(self):
        if CF_API_TOKEN:
            return {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
        elif CF_API_KEY and CF_API_EMAIL:
            return {"X-Auth-Key": CF_API_KEY, "X-Auth-Email": CF_API_EMAIL, "Content-Type": "application/json"}
        else:
            raise RuntimeError("Cloudflare: set CF_API_TOKEN or CF_API_KEY + CF_API_EMAIL")

    def get_zone_id(self, domain: str) -> Optional[str]:
        # Walk up from domain to find the zone
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            resp = _http("GET", f"{self.BASE}/zones", label=f"CF zone lookup {candidate}",
                             headers=self._headers(), params={"name": candidate, "status": "active"})
            data = resp.json()
            if data.get("success") and data.get("result"):
                return data["result"][0]["id"]
        return None

    def _relative_name(self, fqdn: str, domain: str) -> str:
        """Cloudflare expects the full fqdn as 'name'."""
        return fqdn.rstrip(".")

    def list_txt_records(self, zone_id: str, domain: str) -> list[dict]:
        records = []
        page = 1
        while True:
            resp = _http("GET", f"{self.BASE}/zones/{zone_id}/dns_records",
                             label=f"CF list TXT page {page}",
                             headers=self._headers(),
                             params={"type": "TXT", "per_page": 100, "page": page})
            data = resp.json()
            if not data.get("success"):
                log.error("CF list_txt error: %s", data)
                break
            for r in data.get("result", []):
                records.append({"id": r["id"], "name": r["name"], "value": r["content"]})
            info = data.get("result_info", {})
            if page >= info.get("total_pages", 1):
                break
            page += 1
        return records

    def create_txt_record(self, zone_id: str, name: str, value: str, domain: str):
        resp = _http("POST", f"{self.BASE}/zones/{zone_id}/dns_records",
                         label=f"CF create {name}",
                         headers=self._headers(),
                         json={"type": "TXT", "name": self._relative_name(name, domain),
                               "content": value, "ttl": DNS_TTL})
        if not resp.json().get("success"):
            log.error("CF create error for %s: %s", name, resp.text)

    def update_txt_record(self, zone_id: str, record_id: str, name: str, value: str, domain: str):
        resp = _http("PATCH", f"{self.BASE}/zones/{zone_id}/dns_records/{record_id}",
                          label=f"CF update {name}",
                          headers=self._headers(),
                          json={"type": "TXT", "name": self._relative_name(name, domain),
                                "content": value, "ttl": DNS_TTL})
        if not resp.json().get("success"):
            log.error("CF update error for %s: %s", name, resp.text)

    def delete_txt_record(self, zone_id: str, record_id: str, domain: str):
        resp = _http("DELETE", f"{self.BASE}/zones/{zone_id}/dns_records/{record_id}",
                           label=f"CF delete {record_id}",
                           headers=self._headers())
        if not resp.json().get("success"):
            log.error("CF delete error for %s: %s", record_id, resp.text)


# ---------------------------------------------------------------------------
# Route53 Provider
# ---------------------------------------------------------------------------
class Route53Provider(DNSProvider):

    def __init__(self):
        # boto3 is imported here (not at module level) so that Route53 is only
        # a hard dependency when DNS_PROVIDER=route53. Other providers don't pay
        # the boto3 import cost at all.
        import boto3
        self._client = boto3.client(
            "route53",
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY_ID or None,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY or None,
        )

    def get_zone_id(self, domain: str) -> Optional[str]:
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:]) + "."
            resp = self._client.list_hosted_zones_by_name(DNSName=candidate, MaxItems="1")
            for zone in resp.get("HostedZones", []):
                if zone["Name"] == candidate and not zone.get("Config", {}).get("PrivateZone"):
                    return zone["Id"].split("/")[-1]
        return None

    def list_txt_records(self, zone_id: str, domain: str) -> list[dict]:
        records = []
        paginator = self._client.get_paginator("list_resource_record_sets")
        for page in paginator.paginate(HostedZoneId=zone_id):
            for rrs in page["ResourceRecordSets"]:
                if rrs["Type"] == "TXT":
                    name = rrs["Name"].rstrip(".")
                    for rr in rrs.get("ResourceRecords", []):
                        val = rr["Value"].strip('"')
                        records.append({"id": name, "name": name, "value": val})
        return records

    def _change(self, zone_id: str, action: str, name: str, value: str):
        fqdn = name.rstrip(".") + "."
        self._client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{
                "Action": action,
                "ResourceRecordSet": {
                    "Name": fqdn,
                    "Type": "TXT",
                    "TTL": DNS_TTL,
                    "ResourceRecords": [{"Value": f'"{value}"'}],
                }
            }]}
        )

    def create_txt_record(self, zone_id: str, name: str, value: str, domain: str):
        self._change(zone_id, "UPSERT", name, value)

    def update_txt_record(self, zone_id: str, record_id: str, name: str, value: str, domain: str):
        self._change(zone_id, "UPSERT", name, value)

    def delete_txt_record(self, zone_id: str, record_id: str, domain: str):
        # For R53, record_id is the name; we need the current value to delete
        # Use UPSERT/DELETE; to delete we need the exact record
        fqdn = record_id.rstrip(".") + "."
        try:
            resp = self._client.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=fqdn,
                StartRecordType="TXT",
                MaxItems="1",
            )
            for rrs in resp.get("ResourceRecordSets", []):
                if rrs["Name"] == fqdn and rrs["Type"] == "TXT":
                    self._client.change_resource_record_sets(
                        HostedZoneId=zone_id,
                        ChangeBatch={"Changes": [{
                            "Action": "DELETE",
                            "ResourceRecordSet": rrs,
                        }]}
                    )
                    return
        except Exception as e:
            log.error("R53 delete error for %s: %s", record_id, e)

    def upsert_txt(self, zone_id: str, fqdn: str, value: str, domain: str, existing: list[dict]):
        """Route53 UPSERT handles create-or-update natively."""
        log.info("  UPSERT %s", fqdn)
        self._change(zone_id, "UPSERT", fqdn, value)


# ---------------------------------------------------------------------------
# Bunny.net Provider
# ---------------------------------------------------------------------------
class BunnyProvider(DNSProvider):
    BASE = "https://api.bunny.net"

    def __init__(self):
        self._zone_domain_cache: dict[str, str] = {}  # zone_id -> domain name

    def _headers(self):
        return {"AccessKey": BUNNY_API_KEY, "Content-Type": "application/json"}

    def get_zone_id(self, domain: str) -> Optional[str]:
        # List all zones and find the matching one
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            page = 1
            while True:
                resp = _http("GET", f"{self.BASE}/dnszone", label=f"Bunny list zones page {page}",
                                headers=self._headers(), params={"page": page, "perPage": 100})
                data = resp.json()
                items = data.get("Items", data) if isinstance(data, dict) else data
                if isinstance(data, dict):
                    items = data.get("Items", [])
                else:
                    items = data
                for zone in items:
                    if zone.get("Domain", "").lower() == candidate.lower():
                        return str(zone["Id"])
                # Check if more pages
                if isinstance(data, dict) and data.get("HasMoreItems"):
                    page += 1
                else:
                    break
        return None

    def _relative_name(self, fqdn: str, zone_domain: str) -> str:
        """Bunny expects relative name (without zone suffix)."""
        fqdn = fqdn.rstrip(".")
        zone_domain = zone_domain.rstrip(".")
        # Find the actual zone domain by checking what zone we matched
        if fqdn.lower().endswith("." + zone_domain.lower()):
            return fqdn[:-(len(zone_domain) + 1)]
        return fqdn

    def _get_zone_domain(self, zone_id: str) -> str:
        """Fetch the zone domain name from Bunny API (cached per zone_id)."""
        if zone_id not in self._zone_domain_cache:
            resp = _http("GET", f"{self.BASE}/dnszone/{zone_id}", label=f"Bunny zone {zone_id}", headers=self._headers())
            self._zone_domain_cache[zone_id] = resp.json().get("Domain", "")
        return self._zone_domain_cache[zone_id]

    def list_txt_records(self, zone_id: str, domain: str) -> list[dict]:
        resp = _http("GET", f"{self.BASE}/dnszone/{zone_id}", label=f"Bunny list TXT {zone_id}", headers=self._headers())
        data = resp.json()
        zone_domain = data.get("Domain", "")
        records = []
        for r in data.get("Records", []):
            if r.get("Type") == 3:  # TXT
                name_part = r.get("Name", "")
                if name_part:
                    full_name = f"{name_part}.{zone_domain}"
                else:
                    full_name = zone_domain
                records.append({
                    "id": str(r["Id"]),
                    "name": full_name,
                    "value": r.get("Value", ""),
                })
        return records

    def create_txt_record(self, zone_id: str, name: str, value: str, domain: str):
        zone_domain = self._get_zone_domain(zone_id)
        rel_name = self._relative_name(name, zone_domain)
        resp = _http("PUT", f"{self.BASE}/dnszone/{zone_id}/records",
                        label=f"Bunny create {name}",
                        headers=self._headers(),
                        json={"Type": 3, "Name": rel_name, "Value": value, "Ttl": DNS_TTL})
        if resp.status_code not in (200, 201):
            log.error("Bunny create error for %s: %s", name, resp.text)

    def update_txt_record(self, zone_id: str, record_id: str, name: str, value: str, domain: str):
        zone_domain = self._get_zone_domain(zone_id)
        rel_name = self._relative_name(name, zone_domain)
        resp = _http("POST", f"{self.BASE}/dnszone/{zone_id}/records/{record_id}",
                         label=f"Bunny update {name}",
                         headers=self._headers(),
                         json={"Type": 3, "Name": rel_name, "Value": value, "Ttl": DNS_TTL})
        if resp.status_code not in (200, 204):
            log.error("Bunny update error for %s: %s", name, resp.text)

    def delete_txt_record(self, zone_id: str, record_id: str, domain: str):
        resp = _http("DELETE", f"{self.BASE}/dnszone/{zone_id}/records/{record_id}",
                           label=f"Bunny delete {record_id}",
                           headers=self._headers())
        if resp.status_code not in (200, 204):
            log.error("Bunny delete error for %s: %s", record_id, resp.text)


def get_provider() -> DNSProvider:
    p = DNS_PROVIDER.lower()
    if p == "cloudflare":
        return CloudflareProvider()
    elif p == "route53":
        return Route53Provider()
    elif p == "bunny":
        return BunnyProvider()
    else:
        raise RuntimeError(f"Unknown DNS_PROVIDER: {DNS_PROVIDER}. Use cloudflare, route53, or bunny")


_VALID_QUALIFIERS = {"-all", "~all", "+all", "?all"}

def validate_config():
    """Fail fast on missing/invalid configuration before the first DNS cycle."""
    errors = []

    if not MY_DOMAINS:
        errors.append("MY_DOMAINS is not set")

    p = DNS_PROVIDER.lower()
    if p == "cloudflare":
        if not CF_API_TOKEN and not (CF_API_KEY and CF_API_EMAIL):
            errors.append("Cloudflare: set CF_API_TOKEN, or both CF_API_KEY and CF_API_EMAIL")
    elif p == "route53":
        pass  # boto3 supports instance roles; no hard requirement on env vars
    elif p == "bunny":
        if not BUNNY_API_KEY:
            errors.append("Bunny: BUNNY_API_KEY is required")
    else:
        errors.append(f"Unknown DNS_PROVIDER '{DNS_PROVIDER}'. Use cloudflare, route53, or bunny")

    if SPF_ALL_QUAL and SPF_ALL_QUAL not in _VALID_QUALIFIERS:
        errors.append(f"Invalid SPF_ALL_QUALIFIER '{SPF_ALL_QUAL}'. Must be one of: {', '.join(sorted(_VALID_QUALIFIERS))}")

    if errors:
        for e in errors:
            log.error("Config error: %s", e)
        sys.exit(1)


# ===========================================================================
# ALERTING
# ===========================================================================

def send_alerts(subject: str, body: str):
    """Send alert to all configured channels."""
    if SMTP_HOST and SMTP_TO:
        _send_email(subject, body)
    if SLACK_WEBHOOK_URL:
        _send_slack(subject, body)
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        _send_telegram(subject, body)
    if TEAMS_WEBHOOK_URL:
        _send_teams(subject, body)
    if DISCORD_WEBHOOK_URL:
        _send_discord(subject, body)

def _send_email(subject: str, body: str):
    try:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM or SMTP_USER
        msg["To"] = SMTP_TO

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], [a.strip() for a in SMTP_TO.split(",")], msg.as_string())
        log.info("Email alert sent to %s", SMTP_TO)
    except Exception as e:
        log.error("Failed to send email: %s", e)

def _send_slack(subject: str, body: str):
    try:
        payload = {"text": f"*{subject}*\n```\n{body}\n```"}
        resp = _http("POST", SLACK_WEBHOOK_URL, label="Slack alert", json=payload)
        resp.raise_for_status()
        log.info("Slack alert sent")
    except Exception as e:
        log.error("Failed to send Slack alert: %s", e)

def _send_telegram(subject: str, body: str):
    try:
        text = f"<b>{subject}</b>\n<pre>{body}</pre>"
        resp = _http(
            "POST", f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            label="Telegram alert",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
        )
        resp.raise_for_status()
        log.info("Telegram alert sent")
    except Exception as e:
        log.error("Failed to send Telegram alert: %s", e)

def _send_teams(subject: str, body: str):
    try:
        payload = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": subject, "weight": "Bolder", "size": "Medium"},
                        {"type": "TextBlock", "text": body, "wrap": True, "fontType": "Monospace"},
                    ]
                }
            }]
        }
        resp = _http("POST", TEAMS_WEBHOOK_URL, label="Teams alert", json=payload)
        resp.raise_for_status()
        log.info("Teams alert sent")
    except Exception as e:
        log.error("Failed to send Teams alert: %s", e)


def _send_discord(subject: str, body: str):
    try:
        # Discord webhooks accept an "embeds" payload for rich formatting.
        payload = {
            "embeds": [{
                "title": subject,
                "description": f"```\n{body}\n```",
                "color": 0x5865F2,  # Discord blurple
            }]
        }
        resp = _http("POST", DISCORD_WEBHOOK_URL, label="Discord alert", json=payload)
        resp.raise_for_status()
        log.info("Discord alert sent")
    except Exception as e:
        log.error("Failed to send Discord alert: %s", e)


# ===========================================================================
# MAIN PROCESSING
# ===========================================================================

def process_domain(domain: str, provider: DNSProvider) -> bool:
    """
    Process a single domain. Returns True if changes were made.
    """
    source_name = f"{SOURCE_ID}._source.{domain}"
    log.info("Processing domain: %s (source: %s)", domain, source_name)

    # 1. Read the source SPF record
    txts = query_txt(source_name)
    source_spf = None
    for txt in txts:
        if txt.startswith("v=spf1"):
            source_spf = txt
            break

    if not source_spf:
        log.warning("No SPF record found at %s — skipping", source_name)
        return False

    log.info("Source SPF: %s", source_spf)

    # 2. Resolve/flatten the SPF record via the shared engine.
    #    resolve_spf() handles includes, redirects, a, mx, ip4/ip6 recursively.
    #    We resolve source_name itself (which contains the real SPF with all includes),
    #    so the full recursive walk starts from there.
    ips, all_qual = resolve_spf(source_name)

    # Apply override qualifier (validated at startup by validate_config)
    if SPF_ALL_QUAL:
        all_qual = SPF_ALL_QUAL

    log.info("Resolved %d IP mechanisms for %s", len(ips), domain)

    # 3. Build the chained records
    desired_spf = build_spf_records(ips, all_qual, SOURCE_ID, domain)
    new_hash = compute_hash(desired_spf)

    # 4. Check state
    current_hash = get_state_hash(domain)
    log.info("State hash: current=%s new=%s", current_hash or "(none)", new_hash)

    if current_hash == new_hash:
        log.info("No changes detected for %s", domain)
        return False

    # 5. Changes detected — sync DNS
    log.info("Changes detected for %s — syncing %d records", domain, len(desired_spf))

    zone_id = provider.get_zone_id(domain)
    if not zone_id:
        log.error("Could not find DNS zone for %s — skipping", domain)
        return False

    # Add the state record to desired
    state_name = f"{SOURCE_ID}._state.{domain}"
    desired_all = dict(desired_spf)
    desired_all[state_name] = f"spfflat_hash={new_hash}"

    provider.sync_records(zone_id, desired_all, domain)

    # 6. Alert
    alert_body = f"Domain: {domain}\n"
    alert_body += f"Source: {source_name}\n"
    alert_body += f"Old hash: {current_hash or '(first run)'}\n"
    alert_body += f"New hash: {new_hash}\n"
    alert_body += f"Records ({len(desired_spf)}):\n"
    for name, val in sorted(desired_spf.items()):
        alert_body += f"  {name} -> {val}\n"
    alert_body += f"\nResolved {len(ips)} IP mechanisms from source."

    send_alerts(f"[SPF Flattener] Records updated for {domain}", alert_body)

    log.info("Successfully updated %d records for %s", len(desired_spf), domain)
    return True


def run_cycle(provider: DNSProvider):
    """Process all domains."""
    log.info("=== Starting SPF flatten cycle ===")
    log.info("Domains: %s", " ".join(MY_DOMAINS))
    log.info("Source ID: %s | Provider: %s | TTL: %d | Dry run: %s",
             SOURCE_ID, DNS_PROVIDER, DNS_TTL, DRY_RUN)

    changes = 0
    for domain in MY_DOMAINS:
        try:
            if process_domain(domain, provider):
                changes += 1
        except Exception as e:
            log.error("Error processing %s: %s", domain, e)
            log.debug(traceback.format_exc())

    log.info("=== Cycle complete: %d/%d domains updated ===", changes, len(MY_DOMAINS))


def main():
    validate_config()

    log.info("SPF Flattener starting")
    log.info("  SOURCE_ID:    %s", SOURCE_ID)
    log.info("  MY_DOMAINS:   %s", " ".join(MY_DOMAINS))
    log.info("  DNS_PROVIDER: %s", DNS_PROVIDER)
    log.info("  SCHEDULE:     %d minutes", SCHEDULE)
    log.info("  DRY_RUN:      %s", DRY_RUN)

    provider = get_provider()

    if RUN_ONCE:
        run_cycle(provider)
        return

    while not _shutdown:
        run_cycle(provider)
        log.info("Next run in %d minutes…", SCHEDULE)
        # Sleep in small increments to respond to signals
        for _ in range(SCHEDULE * 60):
            if _shutdown:
                break
            time.sleep(1)

    log.info("SPF Flattener stopped.")


if __name__ == "__main__":
    main()