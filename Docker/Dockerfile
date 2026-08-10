# CrowdSec Smart AbuseIPDB Proxy has zero third-party Python dependencies
# (stdlib only: http.server, sqlite3, urllib, ipaddress, argparse, ...),
# so this image needs nothing beyond the interpreter itself. Alpine is
# used specifically to keep it small and resource-light — the official
# python:3.13-alpine image builds CPython from source with sqlite-dev
# present, so `import sqlite3` works out of the box (verified by the
# "docker" CI job in .github/workflows/ci.yml on every push, since this
# specific point has bitten people with *other*, non-official Alpine
# Python builds before).
FROM python:3.13-alpine

LABEL org.opencontainers.image.source="https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy" \
      org.opencontainers.image.description="Deduplicating, rate-limit-aware proxy from CrowdSec alerts to AbuseIPDB" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY abuseipdb_proxy.py .

RUN addgroup -S abuseipdb && adduser -S -G abuseipdb abuseipdb \
    && mkdir -p /var/lib/abuseipdb-proxy \
    && chown abuseipdb:abuseipdb /var/lib/abuseipdb-proxy

USER abuseipdb
VOLUME ["/var/lib/abuseipdb-proxy"]

# PYTHONDONTWRITEBYTECODE: nothing gains from a .pyc cache for a script
# that's read once at container start; skip the (tiny but pointless)
# writes. PYTHONUNBUFFERED: log lines reach `docker logs` immediately
# instead of sitting in a buffer — matters for a process whose whole job
# is timely alerting.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ABUSEIPDB_CACHE_FILE=/var/lib/abuseipdb-proxy/cache.db \
    ABUSEIPDB_LISTEN_ADDRESS=0.0.0.0 \
    ABUSEIPDB_PROXY_PORT=9999 \
    ABUSEIPDB_ENABLE_HEALTH=true
# ABUSEIPDB_API_KEY is deliberately NOT set here — pass it at `docker
# run`/compose time (see docker-compose.env.example), never bake a
# secret into an image layer. ABUSEIPDB_LISTEN_ADDRESS=0.0.0.0 above is
# safe specifically *because* this only runs inside Docker's own network
# isolation (no published port unless you explicitly add one) — see
# docker-compose.yml.

EXPOSE 9999

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "\
import os, sys, urllib.request; \
port = os.environ.get('ABUSEIPDB_PROXY_PORT', '9999'); \
sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=2).status == 200 else 1)" \
    || exit 1

ENTRYPOINT ["python3", "/app/abuseipdb_proxy.py"]
