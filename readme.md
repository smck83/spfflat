# SPF Flattener Container

A Docker container that automatically flattens SPF records, resolving all `include`, `redirect`, `a`, and `mx` mechanisms into raw `ip4`/`ip6` entries. This eliminates the 10 DNS lookup limit problem.

Inspired by [cfspflat](https://github.com/Glocktober/cfspflat) and [r53spflat](https://github.com/Glocktober/r53spflat), but redesigned as a fully stateless container with all configuration via environment variables.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  Your apex record (manually created, never touched by spfflat): │
│  example.com  TXT "v=spf1 redirect=qazwsx3.example.com"        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│  Source record (you maintain this with your real SPF):           │
│  qazwsx3._source.example.com  TXT "v=spf1 include:_spf.goo..." │
│  (can exceed 10 lookups — this is your unflattened truth)       │
└──────────────────────────────┬──────────────────────────────────┘
                               │  spfflat reads & resolves
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  Flattened records (written automatically by spfflat):          │
│  qazwsx3.example.com    TXT "v=spf1 ip4:... include:qazwsx3_1  │
│  qazwsx3_1.example.com  TXT "v=spf1 ip4:... ip6:... ~all"      │
│  qazwsx3._state.example.com TXT "spfflat_hash=abc123..."        │
└─────────────────────────────────────────────────────────────────┘
```

1. **You create** a source SPF record at `{SOURCE_ID}._source.{domain}` containing your real SPF with all includes
2. **You create** an apex redirect: `v=spf1 redirect={SOURCE_ID}.{domain}`
3. **spfflat** reads the source, recursively resolves everything to IPs, and publishes flat chained records at `{SOURCE_ID}.{domain}`, `{SOURCE_ID}_1.{domain}`, etc.
4. **State tracking** via DNS at `{SOURCE_ID}._state.{domain}` — no local files needed
5. **Orphan cleanup** — if the record shrinks (e.g., `qazwsx3_3.example.com` is no longer needed), it's deleted automatically

## Quick Start

### 1. Create your source SPF record

At your DNS provider, create:

```
qazwsx3._source.example.com  TXT  "v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:amazonses.com ~all"
```

### 2. Create the apex redirect

```
example.com  TXT  "v=spf1 redirect=qazwsx3.example.com"
```

### 3. Run with Docker

**Cloudflare:**
```bash
docker run -d --name spfflat \
  -e SOURCE_ID=qazwsx3 \
  -e MY_DOMAINS="example1.com example2.com" \
  -e DNS_PROVIDER=cloudflare \
  -e CF_API_TOKEN=your-cloudflare-api-token \
  -e SCHEDULE=60 \
  spfflat
```

**Route53:**
```bash
docker run -d --name spfflat \
  -e SOURCE_ID=qazwsx3 \
  -e MY_DOMAINS="example.com sub.example.com" \
  -e DNS_PROVIDER=route53 \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e SCHEDULE=60 \
  spfflat
```

**Bunny.net:**
```bash
docker run -d --name spfflat \
  -e SOURCE_ID=qazwsx3 \
  -e MY_DOMAINS="example.com" \
  -e DNS_PROVIDER=bunny \
  -e BUNNY_API_KEY=your-bunny-api-key \
  -e SCHEDULE=60 \
  spfflat
```

### 4. Or use Docker Compose

Copy `docker-compose.yml`, edit the environment variables, then:
```bash
docker compose up -d
```

## Environment Variables

### Required

| Variable | Description | Example |
|---|---|---|
| `MY_DOMAINS` | Space-separated list of domains | `"example.com sub.example.com"` |
| `DNS_PROVIDER` | DNS provider to write records | `cloudflare`, `route53`, or `bunny` |

### Core Settings

| Variable | Default | Description |
|---|---|---|
| `SOURCE_ID` | `qazwsx3` | Prefix for all managed records |
| `SCHEDULE` | `60` | Minutes between checks |
| `DNS_TTL` | `300` | TTL for created TXT records |
| `RESOLVERS` | `1.1.1.1,8.8.8.8` | Comma-separated DNS resolvers |
| `MAX_TXT_LEN` | `450` | Max characters per TXT value (safe under 512) |
| `SPF_ALL_QUALIFIER` | *(from source)* | Override the all qualifier (e.g. `~all`, `-all`) |
| `DRY_RUN` | `false` | Log changes without writing DNS |
| `RUN_ONCE` | `false` | Run one cycle then exit |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Cloudflare Credentials

| Variable | Description |
|---|---|
| `CF_API_TOKEN` | API token (recommended) |
| `CF_API_KEY` | Global API key (legacy, requires `CF_API_EMAIL`) |
| `CF_API_EMAIL` | Account email (used with `CF_API_KEY`) |

### Route53 Credentials

| Variable | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | AWS access key (or use instance role) |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | AWS region (default: `us-east-1`) |

### Bunny.net Credentials

| Variable | Description |
|---|---|
| `BUNNY_API_KEY` | Bunny.net API key from account settings |

### Alerting: Email (SMTP)

All optional. If `SMTP_HOST` and `SMTP_TO` are set, email alerts are sent on changes.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | | SMTP username |
| `SMTP_PASS` | | SMTP password |
| `SMTP_FROM` | | Sender address |
| `SMTP_TO` | | Comma-separated recipients |
| `SMTP_TLS` | `true` | Use STARTTLS |

### Alerting: Slack

| Variable | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |

### Alerting: Telegram

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | Chat/group ID for messages |

### Alerting: MS Teams

| Variable | Description |
|---|---|
| `TEAMS_WEBHOOK_URL` | Teams incoming webhook URL |

## DNS Naming Convention

For `SOURCE_ID=qazwsx3` and domain `example.com`:

| Record | Purpose |
|---|---|
| `qazwsx3._source.example.com` | **You maintain** — your real SPF with all includes |
| `qazwsx3.example.com` | **spfflat writes** — first flattened record (chained) |
| `qazwsx3_1.example.com` | **spfflat writes** — overflow record 1 |
| `qazwsx3_2.example.com` | **spfflat writes** — overflow record 2 (if needed) |
| `qazwsx3._state.example.com` | **spfflat writes** — hash for change detection |

Your apex record should contain: `v=spf1 redirect=qazwsx3.example.com`

## Multi-Domain Support

A single container handles multiple domains. Each domain must have its own `_source` record:

```bash
-e MY_DOMAINS="example.com marketing.example.com partner.co"
```

If `qazwsx3._source.marketing.example.com` doesn't exist, spfflat logs a warning and moves to the next domain.

## Building

```bash
docker build -t spfflat .
```

## Dry Run Mode

Test without writing any DNS changes:

```bash
docker run --rm \
  -e MY_DOMAINS="example.com" \
  -e DNS_PROVIDER=cloudflare \
  -e CF_API_TOKEN=... \
  -e DRY_RUN=true \
  -e RUN_ONCE=true \
  spfflat
```

## License

MIT
