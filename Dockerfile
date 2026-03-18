FROM python:3.12-slim

LABEL maintainer="s@mck.la"
LABEL description="SPF Record Flattener - Cloudflare / Route53 / Bunny.net"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY spfflat.py .

# Non-root user
RUN useradd -r -s /bin/false spfflat
USER spfflat

ENTRYPOINT ["python3", "-u", "spfflat.py"]
