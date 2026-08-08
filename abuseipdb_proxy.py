#!/usr/bin/env python3
"""
CrowdSec Smart AbuseIPDB Proxy

Receives alerts from CrowdSec and forwards them to AbuseIPDB with
deduplication, severity escalation, automatic retries, private-IP
filtering, optional alerting (Gotify/ntfy/Slack/Discord/Matrix/Telegram/
Home Assistant/webhook), and basic
observability endpoints, so repeated or transiently-failing reports for
the same IP don't waste API quota.
"""

import argparse
import hmac
import http.server
import ipaddress
import json
import re
import stat
import subprocess
import time
import urllib.request
import urllib.error
import urllib.parse
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone

VERSION = "2.9.0"

START_TIME = time.time()

LISTEN_PORT = int(os.getenv("ABUSEIPDB_PROXY_PORT", "9999"))
# Bare-metal/LXC default: only reachable from the same host, matching
# CrowdSec's HTTP notification plugin also running locally. In Docker,
# where CrowdSec typically runs in a different container, override to
# "0.0.0.0" and rely on Docker's own network isolation (a dedicated
# compose network, not publishing the port) to keep it from being
# reachable outside that isolated network — see docker-compose.yml.
LISTEN_ADDRESS = os.getenv("ABUSEIPDB_LISTEN_ADDRESS", "127.0.0.1")

# Persistent cache path, survives reboots. Directory must exist
# (the install script creates it, otherwise: mkdir -p /var/lib/abuseipdb-proxy)
#
# Backend: "sqlite" (default since v2.0.0 — a real database with one
# table per section, WAL journal + NORMAL sync by default, which is a
# good balance of speed/write-amplification on an SSD and safe against a
# crash mid-write) or "json" (a single file rewritten atomically on every
# save — simpler to inspect by hand, fine for small setups). An existing
# v1.x cache.json is migrated into the new SQLite cache automatically the
# first time this runs (see _migrate_json_to_sqlite_if_needed below); the
# old file is kept as a .migrated backup, never deleted.
CACHE_BACKEND = os.getenv("ABUSEIPDB_CACHE_BACKEND", "sqlite").strip().lower()
if CACHE_BACKEND not in ("json", "sqlite"):
    # Deliberately not using log() here — it isn't defined yet this early
    # in the file (same reason _validated_pragma below uses a raw write).
    # This one matters more than a bad PRAGMA value would: silently
    # falling through to the JSON code path against a filename picked for
    # SQLite (or vice versa) would mean reading/writing garbage, not just
    # a suboptimal setting.
    sys.stderr.write(
        f"[abuseipdb-proxy] Invalid ABUSEIPDB_CACHE_BACKEND={CACHE_BACKEND!r}, "
        f"expected 'json' or 'sqlite'. Falling back to 'sqlite'.\n"
    )
    CACHE_BACKEND = "sqlite"
_DEFAULT_CACHE_FILE = (
    "/var/lib/abuseipdb-proxy/cache.json" if CACHE_BACKEND == "json"
    else "/var/lib/abuseipdb-proxy/cache.db"
)
CACHE_FILE = os.getenv("ABUSEIPDB_CACHE_FILE", _DEFAULT_CACHE_FILE)

# SQLite PRAGMAs, adjustable for storage that doesn't behave like an SSD
# (e.g. an SD card, where NORMAL synchronous + WAL can still be the right
# call, but some prefer FULL for extra durability at the cost of some
# write amplification) or for anyone with a strong opinion either way.
# Validated against SQLite's actual accepted values before use — an env
# var lands directly in the PRAGMA statement (no parameter binding for
# PRAGMAs in sqlite3), so a typo must fail closed to the safe default
# rather than get executed as-is.
_VALID_JOURNAL_MODES = {"WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"}
_VALID_SYNCHRONOUS = {"OFF", "NORMAL", "FULL", "EXTRA"}


def _validated_pragma(env_var, default, valid_values):
    value = os.getenv(env_var, default).strip().upper()
    if value not in valid_values:
        sys.stderr.write(
            f"[abuseipdb-proxy] Invalid {env_var}={value!r}, "
            f"expected one of {sorted(valid_values)}. Using default {default!r}.\n"
        )
        return default
    return value


CACHE_SQLITE_JOURNAL_MODE = _validated_pragma("ABUSEIPDB_SQLITE_JOURNAL_MODE", "WAL", _VALID_JOURNAL_MODES)
CACHE_SQLITE_SYNCHRONOUS = _validated_pragma("ABUSEIPDB_SQLITE_SYNCHRONOUS", "NORMAL", _VALID_SYNCHRONOUS)


def _get_secret(name, default=""):
    """
    Reads `name` from its env var, or from the file at `{name}_FILE` if
    that's set instead — the Docker/Podman secrets convention (mount a
    file, point *_FILE at it) so the actual value never has to sit in
    plain text in docker-compose.env/abuseipdb-proxy.env on disk or show
    up in `docker inspect`/`ps`. If both are set, the _FILE variant wins.

    Deliberately uses a bare sys.stderr.write for its own error
    reporting, the same as _validated_pragma() right above — NOT log(),
    because this runs at module-import time before log() is defined
    (API_KEY, right below, needs this immediately). Every other secret
    this is used for further down in the file is defined after log()
    exists, but this stays log()-free everywhere for consistency, so
    moving one of those calls around later can't quietly reintroduce the
    same ordering trap.
    """
    file_path = os.getenv(f"{name}_FILE", "").strip()
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError as e:
            sys.stderr.write(
                f"[abuseipdb-proxy] Warning: could not read {name}_FILE "
                f"({file_path}): {e}. Falling back to {name} if set.\n"
            )
    return os.getenv(name, default)


# No default anymore: the proxy intentionally refuses to start without a key
# (unless --dry-run / ABUSEIPDB_DRY_RUN is active, see below).
API_KEY = _get_secret("ABUSEIPDB_API_KEY") or None

# "text" (default): the traditional "[abuseipdb-proxy] message" line.
# "json": one JSON object per line (timestamp/level/message + any extra
# structured fields a call site passes) — for Loki/ELK/Graylog etc.
# Always written to stderr either way, which is what systemd/journald
# expects from a service's own logging.
LOG_FORMAT = os.getenv("ABUSEIPDB_LOG_FORMAT", "text").strip().lower()


def log(message, level="info", **fields):
    if LOG_FORMAT == "json":
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
        }
        record.update(fields)
        sys.stderr.write(json.dumps(record) + "\n")
    else:
        sys.stderr.write(f"[abuseipdb-proxy] {message}\n")

# Default time window in seconds during which a report for the same IP is
# either suppressed or delayed until an escalation is due. Can be overridden
# per severity tier below.
DEFAULT_REPORT_WINDOW = int(os.getenv("ABUSEIPDB_REPORT_WINDOW", "905"))

REPORT_WINDOWS = {
    1: int(os.getenv("ABUSEIPDB_REPORT_WINDOW_LOW", str(DEFAULT_REPORT_WINDOW))),
    2: int(os.getenv("ABUSEIPDB_REPORT_WINDOW_MEDIUM", str(DEFAULT_REPORT_WINDOW))),
    3: int(os.getenv("ABUSEIPDB_REPORT_WINDOW_HIGH", str(DEFAULT_REPORT_WINDOW))),
}

# Retry behavior for failed API calls (network errors, AbuseIPDB downtime,
# or 429 rate limiting). Defaults to AbuseIPDB's own ~15 minute per-IP
# report cooldown, which is the most common reason for a 429 here.
MAX_RETRIES = int(os.getenv("ABUSEIPDB_MAX_RETRIES", "3"))
RETRY_DELAY = int(os.getenv("ABUSEIPDB_RETRY_DELAY", "900"))

# If true, log what would be reported instead of actually calling the
# AbuseIPDB API. Useful for testing new CrowdSec scenarios without burning
# API quota. Can also be enabled with --dry-run on the command line.
DRY_RUN = os.getenv("ABUSEIPDB_DRY_RUN", "false").strip().lower() in ("1", "true", "yes")

# Per-event log lines (one line per successful report, one per ignored
# private IP) are OFF by default. Under a honeypot or any high-volume
# CrowdSec setup, logging every single event can flood the journal /
# consume disk or RAM. Instead, a periodic one-line summary is logged
# (see ABUSEIPDB_SUMMARY_INTERVAL below). Set this to true for
# troubleshooting on a low-traffic host where per-event detail is useful.
VERBOSE_LOGGING = os.getenv("ABUSEIPDB_VERBOSE_LOGGING", "false").strip().lower() in ("1", "true", "yes")

# Interval in seconds for the periodic summary log line (sent/suppressed/
# failed/ignored counts since the last summary). Set to 0 to disable.
# Only logs when something actually happened in that window — no empty
# "nothing to report" spam during quiet periods.
SUMMARY_INTERVAL = int(os.getenv("ABUSEIPDB_SUMMARY_INTERVAL", "300"))

# GET /health and GET /metrics are OFF by default — opt in explicitly if
# you want them. Both are already bound to 127.0.0.1 only, but default to
# minimal attack surface / minimal footprint until you decide you want
# observability.
ENABLE_HEALTH = os.getenv("ABUSEIPDB_ENABLE_HEALTH", "false").strip().lower() in ("1", "true", "yes")
ENABLE_METRICS = os.getenv("ABUSEIPDB_ENABLE_METRICS", "false").strip().lower() in ("1", "true", "yes")

# Optional: send a (low-priority) notification through the configured
# alerting backend(s) every time the proxy starts. Handy after an update
# or restart, to get an immediate confirmation instead of manually
# checking `systemctl status`. Off by default — routine restarts aren't
# usually worth an alert.
NOTIFY_ON_START = os.getenv("ABUSEIPDB_NOTIFY_ON_START", "false").strip().lower() in ("1", "true", "yes")

# --- Reconciliation (--reconcile) --------------------------------------
# Not part of the normal request path — a standalone catch-up job, like
# --backup/--vacuum, meant for a periodic timer. Compares CrowdSec's
# currently active decisions (via its local API, the same one bouncers
# use) against this proxy's own report cache, and reports anything
# CrowdSec has banned that never made it to AbuseIPDB — e.g. because the
# proxy was down when the notification plugin fired. Requires a CrowdSec
# bouncer API key (`cscli bouncers add <name>`); off/inert without one.
CROWDSEC_LAPI_URL = os.getenv("ABUSEIPDB_CROWDSEC_LAPI_URL", "http://127.0.0.1:8080").rstrip("/")
CROWDSEC_BOUNCER_KEY = _get_secret("ABUSEIPDB_CROWDSEC_BOUNCER_KEY").strip()
# Fallback only — used when a decision has no usable scenario name (e.g.
# one added manually via `cscli decisions add`, which has no scenario at
# all). Whenever a scenario name IS available, SCENARIO_CATEGORY_RULES
# below is used instead, the same as a live alert would be.
RECONCILE_SEVERITY = int(os.getenv("ABUSEIPDB_RECONCILE_SEVERITY", "2"))
RECONCILE_CATEGORIES = os.getenv("ABUSEIPDB_RECONCILE_CATEGORIES", "15").strip()

# This MUST stay in sync with abuseipdb.yaml's `format` template — same
# substrings, same categories, same order (first match wins, exactly like
# the Go template's if/else-if chain). It exists so --reconcile can
# categorize a missing report the same way the live path would have,
# instead of falling back to a fixed guess. tests/test_scenario_mapping.py
# parses abuseipdb.yaml itself and cross-checks it against this list, so
# the two can't silently drift apart.
SCENARIO_CATEGORY_RULES = [
    ("ssh", "18,22"),
    ("telnet", "18,23"),
    ("ftp", "5,18"),
    ("vsftpd", "5,18"),
    ("mysql", "18"),
    ("pop3", "18"),
    ("imap", "18"),
    ("dovecot", "18"),
    ("spam", "11"),
    ("sqli", "16,21"),
    ("xss", "21"),
    ("path-traversal", "21"),
    ("open-proxy", "9"),
    ("backdoor", "15,20"),
    ("bad-user-agent", "19"),
    ("sensitive-files", "21"),
    ("probing", "21"),
    ("scan", "14"),
    ("crawl", "19"),
    ("ddos", "4"),
    ("dos", "4"),
    ("bruteforce", "18"),
    ("-bf", "18"),
    ("cve", "15,21"),
    ("http", "21"),
    ("exploit", "15,21"),
]
SCENARIO_CATEGORY_DEFAULT = "15"


def categories_for_scenario(scenario):
    """Same substring-match logic as abuseipdb.yaml's Go template: first
    rule whose substring appears in the (lowercased) scenario name wins.
    Returns None if `scenario` is empty/falsy, so the caller can tell
    "no scenario available" apart from "no rule matched" (which still
    returns the default categories, exactly like the template does)."""
    if not scenario:
        return None
    scenario = scenario.lower()
    for substring, categories in SCENARIO_CATEGORY_RULES:
        if substring in scenario:
            return categories
    return SCENARIO_CATEGORY_DEFAULT


# Off by default: querying AbuseIPDB's own /v2/check endpoint before every
# report costs a separate daily quota from /v2/report, and adds a
# synchronous network round-trip on the request path (the proxy's HTTP
# server is single-threaded, so a slow check briefly delays whatever's
# next in line — mitigated by the per-IP cache below, but worth knowing
# before enabling this on a high-traffic setup). When on, skips reporting
# an IP AbuseIPDB itself already marks as "isWhitelisted" (e.g. well-known
# crawlers/CDNs that opted in) — no point spending report quota on those.
SKIP_WHITELISTED = os.getenv("ABUSEIPDB_SKIP_WHITELISTED", "false").strip().lower() in ("1", "true", "yes")
WHITELIST_CACHE_TTL = int(os.getenv("ABUSEIPDB_WHITELIST_CACHE_TTL", "86400"))

# --- Private / reserved IP filtering ---------------------------------------
# Reporting RFC1918, loopback, link-local, or CGNAT addresses to AbuseIPDB
# never makes sense (they're not publicly routable / not attributable to a
# real abuser). CGNAT (100.64.0.0/10) is included since it's also the range
# Tailscale uses internally — worth excluding if CrowdSec ever sees
# Tailscale-internal traffic.
IGNORE_PRIVATE = os.getenv("ABUSEIPDB_IGNORE_PRIVATE", "true").strip().lower() in ("1", "true", "yes")

_DEFAULT_IGNORE_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC1918
    "127.0.0.0/8",       # IPv4 loopback
    "169.254.0.0/16",    # IPv4 link-local
    "100.64.0.0/10",     # CGNAT (also used by Tailscale)
    "::1/128",            # IPv6 loopback
    "fc00::/7",           # IPv6 unique local
    "fe80::/10",          # IPv6 link-local
    # RFC 5737 / RFC 3849: reserved exclusively for documentation and
    # examples, never assigned to a real host — can't ever be a genuine
    # attacker. Also what --check-config --live's synthetic self-test
    # alert uses (192.0.2.1), which relies on it always landing here
    # rather than ever reaching the real AbuseIPDB API.
    "192.0.2.0/24",       # TEST-NET-1
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "2001:db8::/32",      # IPv6 documentation range
]


def _build_ignore_networks():
    nets = []
    if IGNORE_PRIVATE:
        for cidr in _DEFAULT_IGNORE_NETWORKS:
            try:
                nets.append(ipaddress.ip_network(cidr))
            except ValueError:
                pass
    for item in os.getenv("ABUSEIPDB_IGNORE_IPS", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log(f"Warning: could not parse ABUSEIPDB_IGNORE_IPS entry '{item}', skipping.",
                level="warning", entry=item)
    return nets


IGNORE_NETWORKS = _build_ignore_networks()


def is_ignored_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False  # malformed IP: let AbuseIPDB reject it, don't crash here
    return any(addr.version == net.version and addr in net for net in IGNORE_NETWORKS)


# --- Local-port access control ----------------------------------------------
# The proxy has no auth of its own by design (see README's "Known
# limitations") since it's meant to stay on 127.0.0.1 or inside an
# isolated Docker network. Both controls below are optional extra layers
# for setups where that boundary is less clean-cut (e.g.
# ABUSEIPDB_LISTEN_ADDRESS=0.0.0.0 without a dedicated compose network, or
# just wanting defense-in-depth). Neither is required and both are off by
# default.
ALLOWED_SOURCE_IPS = os.getenv("ABUSEIPDB_ALLOWED_SOURCE_IPS", "")
SHARED_SECRET = _get_secret("ABUSEIPDB_SHARED_SECRET")


def _build_allowed_source_networks():
    nets = []
    for item in ALLOWED_SOURCE_IPS.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log(f"Warning: could not parse ABUSEIPDB_ALLOWED_SOURCE_IPS entry '{item}', skipping.",
                level="warning", entry=item)
    return nets


ALLOWED_SOURCE_NETWORKS = _build_allowed_source_networks()


def is_source_ip_allowed(client_ip):
    """Empty ABUSEIPDB_ALLOWED_SOURCE_IPS (the default) means no
    allowlist is enforced — matches the current behavior."""
    if not ALLOWED_SOURCE_NETWORKS:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in ALLOWED_SOURCE_NETWORKS)


def is_shared_secret_valid(provided):
    """Empty ABUSEIPDB_SHARED_SECRET (the default) means no secret is
    required — matches the current behavior. Constant-time comparison so
    the check itself can't be used to brute-force the secret via timing."""
    if not SHARED_SECRET:
        return True
    return hmac.compare_digest(provided or "", SHARED_SECRET)


# --- Concurrent-request ceiling ---------------------------------------------
# Since v2.8.0's switch to ThreadingHTTPServer, every connection gets its
# own thread with no upper bound. CrowdSec itself is trusted, so this
# isn't really about defending against abuse — it's a safety net against
# a misconfiguration or bug (a scenario loop, a flood of decisions) piling
# up an unbounded number of threads. 0 disables the limit entirely.
# Rejection is immediate (non-blocking), not a queued wait — this is meant
# to fail fast and loud under a genuinely abnormal load, not to smooth
# over ordinary bursts (the default of 50 is well above what any real
# CrowdSec setup should ever produce at once).
MAX_CONCURRENT_REQUESTS = int(os.getenv("ABUSEIPDB_MAX_CONCURRENT_REQUESTS", "50"))
_request_semaphore = threading.Semaphore(MAX_CONCURRENT_REQUESTS) if MAX_CONCURRENT_REQUESTS > 0 else None


# --- Alerting (Gotify / ntfy / Slack / Discord / Matrix / Telegram / -------
# --- Home Assistant / generic webhook) --------------------------------------
# All optional. Each backend activates itself as soon as its required
# variable(s) are set — no extra "enable" flag needed. Each backend is
# handled idiomatically for that platform (Gotify's JSON+token, ntfy's
# header-based API, Matrix's Client-Server API, ...) so you only need to
# supply the URL/token(s). Multiple backends can run at once.
NOTIFY_NAME = os.getenv("ABUSEIPDB_NOTIFY_NAME", "CrowdSec Smart AbuseIPDB Proxy")

GOTIFY_URL = os.getenv("ABUSEIPDB_GOTIFY_URL", "").rstrip("/")
GOTIFY_TOKEN = _get_secret("ABUSEIPDB_GOTIFY_TOKEN")

NTFY_URL = os.getenv("ABUSEIPDB_NTFY_URL", "").rstrip("/")
NTFY_TOKEN = _get_secret("ABUSEIPDB_NTFY_TOKEN")

WEBHOOK_URL = _get_secret("ABUSEIPDB_WEBHOOK_URL")

SLACK_WEBHOOK_URL = _get_secret("ABUSEIPDB_SLACK_WEBHOOK_URL")

DISCORD_WEBHOOK_URL = _get_secret("ABUSEIPDB_DISCORD_WEBHOOK_URL")

# Matrix has no webhook concept of its own — this posts directly via the
# Client-Server API, so it needs a homeserver, an access token for the
# sending account (e.g. a dedicated bot user), and the room to post into.
MATRIX_HOMESERVER_URL = os.getenv("ABUSEIPDB_MATRIX_HOMESERVER_URL", "").rstrip("/")
MATRIX_ACCESS_TOKEN = _get_secret("ABUSEIPDB_MATRIX_ACCESS_TOKEN")
MATRIX_ROOM_ID = os.getenv("ABUSEIPDB_MATRIX_ROOM_ID", "")

TELEGRAM_BOT_TOKEN = _get_secret("ABUSEIPDB_TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("ABUSEIPDB_TELEGRAM_CHAT_ID", "")

# Native Home Assistant notify.* service call via its REST API — no
# separate bridge needed, just a Long-Lived Access Token from a HA user
# profile. HOMEASSISTANT_NOTIFY_SERVICE is the part after "notify." in
# the service name (default "notify" = the generic notify.notify
# service; set it to e.g. "mobile_app_myphone" to target one device).
HOMEASSISTANT_URL = os.getenv("ABUSEIPDB_HOMEASSISTANT_URL", "").rstrip("/")
HOMEASSISTANT_TOKEN = _get_secret("ABUSEIPDB_HOMEASSISTANT_TOKEN")
HOMEASSISTANT_NOTIFY_SERVICE = os.getenv("ABUSEIPDB_HOMEASSISTANT_NOTIFY_SERVICE", "notify")

_GOTIFY_PRIORITY = {"low": 2, "normal": 5, "high": 8}
_NTFY_PRIORITY = {"low": "low", "normal": "default", "high": "high"}
_EMOJI_PRIORITY = {"low": "\U0001F535", "normal": "\U0001F7E1", "high": "\U0001F534"}  # blue/yellow/red


def _notify_gotify(message, priority):
    try:
        url = f"{GOTIFY_URL}/message?token={urllib.parse.quote(GOTIFY_TOKEN)}"
        body = json.dumps({
            "title": NOTIFY_NAME,
            "message": message,
            "priority": _GOTIFY_PRIORITY.get(priority, 5),
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Gotify notification failed: {e}", level="warning", backend="gotify")


def _notify_ntfy(message, priority):
    try:
        headers = {
            "Title": NOTIFY_NAME,
            "Priority": _NTFY_PRIORITY.get(priority, "default"),
            "Content-Type": "text/plain; charset=utf-8",
        }
        if NTFY_TOKEN:
            headers["Authorization"] = f"Bearer {NTFY_TOKEN}"
        req = urllib.request.Request(NTFY_URL, data=message.encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"ntfy notification failed: {e}", level="warning", backend="ntfy")


def _notify_webhook(message, priority):
    try:
        body = json.dumps({"name": NOTIFY_NAME, "message": message, "priority": priority}).encode("utf-8")
        req = urllib.request.Request(WEBHOOK_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Webhook notification failed: {e}", level="warning", backend="webhook")


def _notify_slack(message, priority):
    try:
        emoji = _EMOJI_PRIORITY.get(priority, "")
        text = f"{emoji} *{NOTIFY_NAME}*\n{message}"
        body = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(SLACK_WEBHOOK_URL, data=body,
                                      headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Slack notification failed: {e}", level="warning", backend="slack")


def _notify_discord(message, priority):
    try:
        emoji = _EMOJI_PRIORITY.get(priority, "")
        # Discord webhook messages cap at 2000 characters.
        content = f"{emoji} **{NOTIFY_NAME}**\n{message}"[:2000]
        body = json.dumps({"content": content, "username": NOTIFY_NAME}).encode("utf-8")
        req = urllib.request.Request(DISCORD_WEBHOOK_URL, data=body,
                                      headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Discord notification failed: {e}", level="warning", backend="discord")


def _notify_matrix(message, priority):
    try:
        # Matrix has no webhooks of its own: post directly via the
        # Client-Server API's "send message event" endpoint. The
        # transaction ID just needs to be unique per request from this
        # client, so a millisecond timestamp is sufficient here.
        txn_id = str(int(time.time() * 1000))
        url = (
            f"{MATRIX_HOMESERVER_URL}/_matrix/client/v3/rooms/"
            f"{urllib.parse.quote(MATRIX_ROOM_ID)}/send/m.room.message/{txn_id}"
        )
        body_text = f"{NOTIFY_NAME}: {message}"
        payload = json.dumps({"msgtype": "m.text", "body": body_text}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MATRIX_ACCESS_TOKEN}",
        }, method="PUT")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Matrix notification failed: {e}", level="warning", backend="matrix")


def _notify_telegram(message, priority):
    try:
        emoji = _EMOJI_PRIORITY.get(priority, "")
        text = f"{emoji} *{NOTIFY_NAME}*\n{message}"
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        body = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Telegram notification failed: {e}", level="warning", backend="telegram")


def _notify_homeassistant(message, priority):
    try:
        # Home Assistant's REST API: POST /api/services/notify/<service>
        # with {"message": ...} calls that notify.<service> service —
        # the exact same thing a "service: notify.xxx" automation action
        # does, just triggered over HTTP instead of from within HA.
        url = f"{HOMEASSISTANT_URL}/api/services/notify/{HOMEASSISTANT_NOTIFY_SERVICE}"
        body = json.dumps({
            "message": message,
            "title": NOTIFY_NAME,
            "data": {"priority": priority},
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {HOMEASSISTANT_TOKEN}",
        }, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log(f"Home Assistant notification failed: {e}", level="warning", backend="homeassistant")


def notify(message, priority="high"):
    """Fire-and-forget alert to any configured backend(s). Never raises and
    never blocks the caller — a broken notification backend must not affect
    report delivery."""
    if GOTIFY_URL and GOTIFY_TOKEN:
        threading.Thread(target=_notify_gotify, args=(message, priority), daemon=True).start()
    if NTFY_URL:
        threading.Thread(target=_notify_ntfy, args=(message, priority), daemon=True).start()
    if WEBHOOK_URL:
        threading.Thread(target=_notify_webhook, args=(message, priority), daemon=True).start()
    if SLACK_WEBHOOK_URL:
        threading.Thread(target=_notify_slack, args=(message, priority), daemon=True).start()
    if DISCORD_WEBHOOK_URL:
        threading.Thread(target=_notify_discord, args=(message, priority), daemon=True).start()
    if MATRIX_HOMESERVER_URL and MATRIX_ACCESS_TOKEN and MATRIX_ROOM_ID:
        threading.Thread(target=_notify_matrix, args=(message, priority), daemon=True).start()
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        threading.Thread(target=_notify_telegram, args=(message, priority), daemon=True).start()
    if HOMEASSISTANT_URL and HOMEASSISTANT_TOKEN:
        threading.Thread(target=_notify_homeassistant, args=(message, priority), daemon=True).start()


# --- Metrics -----------------------------------------------------------
metrics_lock = threading.Lock()
metrics = {
    "reports_sent_total": 0,
    "reports_suppressed_total": 0,
    "reports_failed_total": 0,
    "reports_ignored_private_total": 0,
    "reports_quota_reserved_total": 0,
    "reports_whitelisted_total": 0,
    "reports_rejected_overload_total": 0,
}


def inc_metric(name, n=1):
    with metrics_lock:
        metrics[name] = metrics.get(name, 0) + n


def _summary_loop():
    """Logs one summary line every SUMMARY_INTERVAL seconds, instead of a
    line per event — keeps the journal readable (and small) even under
    honeypot-level traffic. Silent during quiet periods (no activity ->
    no line)."""
    last_snapshot = {k: 0 for k in metrics}
    while True:
        time.sleep(SUMMARY_INTERVAL)
        with metrics_lock:
            snapshot = dict(metrics)
        deltas = {k: snapshot.get(k, 0) - last_snapshot.get(k, 0) for k in snapshot}
        last_snapshot = snapshot
        if sum(deltas.values()) == 0:
            continue
        log(
            f"Summary (last {SUMMARY_INTERVAL}s): "
            f"{deltas.get('reports_sent_total', 0)} sent, "
            f"{deltas.get('reports_suppressed_total', 0)} suppressed, "
            f"{deltas.get('reports_failed_total', 0)} failed, "
            f"{deltas.get('reports_ignored_private_total', 0)} ignored (private).",
            sent=deltas.get("reports_sent_total", 0),
            suppressed=deltas.get("reports_suppressed_total", 0),
            failed=deltas.get("reports_failed_total", 0),
            ignored_private=deltas.get("reports_ignored_private_total", 0),
        )


# AbuseIPDB's full category list (https://www.abuseipdb.com/categories),
# mapped to an internal 1 (low) - 3 (high) severity used for deduplication
# and escalation. Categories not relevant to typical CrowdSec scenarios
# (e.g. Fraud Orders, Fraud VoIP) are included for completeness in case a
# custom scenario ever reports them.
SEVERITY_MAP = {
    "1":  3,  # DNS Compromise
    "2":  3,  # DNS Poisoning
    "3":  2,  # Fraud Orders
    "4":  3,  # DDoS Attack
    "5":  2,  # FTP Brute-Force
    "6":  2,  # Ping of Death
    "7":  3,  # Phishing
    "8":  2,  # Fraud VoIP
    "9":  1,  # Open Proxy
    "10": 1,  # Web Spam
    "11": 1,  # Email Spam
    "12": 1,  # Blog Spam
    "13": 1,  # VPN IP
    "14": 1,  # Port Scan
    "15": 3,  # Hacking
    "16": 3,  # SQL Injection
    "17": 2,  # Spoofing
    "18": 2,  # Brute-Force
    "19": 1,  # Bad Web Bot
    "20": 3,  # Exploited Host
    "21": 2,  # Web App Attack
    "22": 2,  # SSH
    "23": 2,  # IoT Targeted
}

# RLock, not Lock: process_alert() holds this for its entire decide-then-write
# sequence and can call _schedule_pending() from inside that same block,
# which itself needs to acquire this lock to be safe if ever called from
# somewhere else in the future. A plain Lock would deadlock on that nested
# acquire (same thread re-entering); RLock allows it.
lock = threading.RLock()
pending_timers = {}  # ip -> {"timer": threading.Timer, "severity": int}
retry_timers = {}    # ip -> threading.Timer
_cache_write_failing = False


def get_severity(categories_str):
    cats = [c.strip() for c in categories_str.split(",") if c.strip()]
    score = 1
    for c in cats:
        score = max(score, SEVERITY_MAP.get(c, 1))
    return score


def _parse_category_windows(raw):
    """Parses ABUSEIPDB_REPORT_WINDOW_CATEGORIES, a comma-separated
    "category=seconds" list (e.g. "16=1800,20=3600"), into a dict. Lets
    specific categories get their own dedup/escalation window instead of
    sharing their severity tier's window with every other category at
    the same severity — the finer-than-severity granularity called out
    as a known limitation in the README."""
    windows = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            log(f"Warning: could not parse ABUSEIPDB_REPORT_WINDOW_CATEGORIES entry "
                f"'{item}' (expected category=seconds), skipping.",
                level="warning", entry=item)
            continue
        cat, _, secs = item.partition("=")
        cat = cat.strip()
        try:
            windows[cat] = int(secs.strip())
        except ValueError:
            log(f"Warning: invalid window value in ABUSEIPDB_REPORT_WINDOW_CATEGORIES "
                f"entry '{item}', skipping.", level="warning", entry=item)
    return windows


CATEGORY_WINDOWS = _parse_category_windows(os.getenv("ABUSEIPDB_REPORT_WINDOW_CATEGORIES", ""))


def get_report_window(severity, categories_str=""):
    """Category overrides win over the severity-tier default. If an alert
    carries more than one overridden category, the smallest (most
    restrictive) window applies, so an escalation is never held back
    longer than its most urgent category warrants."""
    if CATEGORY_WINDOWS and categories_str:
        cats = [c.strip() for c in categories_str.split(",") if c.strip()]
        overrides = [CATEGORY_WINDOWS[c] for c in cats if c in CATEGORY_WINDOWS]
        if overrides:
            return min(overrides)
    return REPORT_WINDOWS.get(severity, DEFAULT_REPORT_WINDOW)


def ensure_cache_dir():
    cache_dir = os.path.dirname(CACHE_FILE)
    if cache_dir and not os.path.isdir(cache_dir):
        os.makedirs(cache_dir, mode=0o700, exist_ok=True)


def load_cache():
    """
    Returns the cache as:
    {
      "reports": {ip: {"time": epoch, "severity": int}},
      "pending": {ip: {"due_time": epoch, "severity": int,
                        "categories": str, "comment": str}},
      "retry_queue": {ip: {"due_time": epoch, "categories": str,
                            "comment": str, "attempts": int}}
    }
    regardless of which backend (JSON file or SQLite database) is active.
    """
    if CACHE_BACKEND == "sqlite":
        return _load_cache_sqlite()
    return _load_cache_json()


def save_cache(cache):
    global _cache_write_failing
    try:
        if CACHE_BACKEND == "sqlite":
            _save_cache_sqlite(cache)
        else:
            _save_cache_json(cache)
        _cache_write_failing = False
    except Exception as e:
        log(f"Failed to write cache: {e}", level="error")
        if not _cache_write_failing:
            _cache_write_failing = True
            notify(f"Failed to write cache file at {CACHE_FILE}: {e}", priority="high")


def _load_cache_json():
    """
    Older versions of this script wrote a flat {ip: {"time", "severity"}}
    structure with no "pending"/"retry_queue" sections, or (v1.1.0) a
    structure without "retry_queue". Both are transparently upgraded on
    first load.
    """
    if not os.path.exists(CACHE_FILE):
        return {"reports": {}, "pending": {}, "retry_queue": {}}
    try:
        with open(CACHE_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        return {"reports": {}, "pending": {}, "retry_queue": {}}

    if "reports" in data or "pending" in data or "retry_queue" in data:
        data.setdefault("reports", {})
        data.setdefault("pending", {})
        data.setdefault("retry_queue", {})
        return data

    # Legacy flat format (v1.0.0): the whole dict was the "reports" map.
    return {"reports": data, "pending": {}, "retry_queue": {}}


def _save_cache_json(cache):
    ensure_cache_dir()
    tmp_path = CACHE_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(cache, f)
    os.replace(tmp_path, CACHE_FILE)


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    ip TEXT PRIMARY KEY,
    time INTEGER NOT NULL,
    severity INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending (
    ip TEXT PRIMARY KEY,
    due_time INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    categories TEXT NOT NULL,
    comment TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS retry_queue (
    ip TEXT PRIMARY KEY,
    due_time INTEGER NOT NULL,
    categories TEXT NOT NULL,
    comment TEXT NOT NULL,
    attempts INTEGER NOT NULL
);
"""


def _sqlite_connect(path=None):
    ensure_cache_dir()
    conn = sqlite3.connect(path or CACHE_FILE, timeout=10)
    # Values validated at import time (see _validated_pragma above), so
    # this f-string is safe despite PRAGMA not supporting parameter
    # binding in the sqlite3 module.
    conn.execute(f"PRAGMA journal_mode={CACHE_SQLITE_JOURNAL_MODE}")
    conn.execute(f"PRAGMA synchronous={CACHE_SQLITE_SYNCHRONOUS}")
    conn.executescript(_SQLITE_SCHEMA)
    return conn


def _migrate_json_to_sqlite_if_needed():
    """
    v2.0.0 switched the default cache backend from a single JSON file to
    SQLite. If this is a brand-new SQLite cache (the .db file doesn't
    exist yet) and a legacy cache.json is sitting in the same directory,
    import it once so existing report history isn't silently lost on
    upgrade. The old file is renamed — never deleted — immediately after
    a successful import, so this only ever runs once per install and a
    backup always remains on disk.
    """
    if os.path.exists(CACHE_FILE):
        return  # already has its own history (or was already migrated)

    legacy_path = os.path.join(os.path.dirname(CACHE_FILE) or ".", "cache.json")
    if legacy_path == CACHE_FILE or not os.path.exists(legacy_path):
        return

    log(
        f"Found a legacy JSON cache at {legacy_path}; "
        f"migrating it into the new SQLite cache at {CACHE_FILE}...",
        legacy_path=legacy_path, target_path=CACHE_FILE,
    )
    try:
        with open(legacy_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        log(f"Could not read legacy cache, starting empty: {e}", level="warning")
        return

    if "reports" in data or "pending" in data or "retry_queue" in data:
        data.setdefault("reports", {})
        data.setdefault("pending", {})
        data.setdefault("retry_queue", {})
    else:
        data = {"reports": data, "pending": {}, "retry_queue": {}}  # v1.0.0 flat format

    try:
        _save_cache_sqlite(data)
    except Exception as e:
        log(f"Migration to SQLite failed, leaving legacy file in place: {e}", level="error")
        return

    entry_count = sum(len(section) for section in data.values())
    backup_path = legacy_path + ".migrated"
    try:
        os.replace(legacy_path, backup_path)
    except OSError as e:
        log(f"Migrated, but couldn't rename the old file: {e}", level="warning")
        backup_path = legacy_path

    log(
        f"Migration complete: {entry_count} entries imported. "
        f"Old file kept as {backup_path}.",
        entries=entry_count, backup_path=backup_path,
    )
    notify(
        f"Migrated legacy JSON cache to SQLite ({CACHE_FILE}, {entry_count} entries). "
        f"Old file backed up as {os.path.basename(backup_path)}.",
        priority="normal",
    )


def _load_cache_sqlite():
    _migrate_json_to_sqlite_if_needed()
    try:
        conn = _sqlite_connect()
    except sqlite3.Error as e:
        log(f"Failed to open SQLite cache, starting empty: {e}", level="error")
        return {"reports": {}, "pending": {}, "retry_queue": {}}

    try:
        reports = {
            ip: {"time": t, "severity": s}
            for ip, t, s in conn.execute("SELECT ip, time, severity FROM reports")
        }
        pending = {
            ip: {"due_time": due, "severity": sev, "categories": cats, "comment": comment}
            for ip, due, sev, cats, comment in
            conn.execute("SELECT ip, due_time, severity, categories, comment FROM pending")
        }
        retry_queue = {
            ip: {"due_time": due, "categories": cats, "comment": comment, "attempts": attempts}
            for ip, due, cats, comment, attempts in
            conn.execute("SELECT ip, due_time, categories, comment, attempts FROM retry_queue")
        }
        return {"reports": reports, "pending": pending, "retry_queue": retry_queue}
    finally:
        conn.close()


def _save_cache_sqlite(cache, path=None):
    conn = _sqlite_connect(path)
    try:
        with conn:  # single transaction: either the whole cache is
                    # replaced, or (on error) none of it is — same
                    # all-or-nothing guarantee the atomic JSON rename gives
            conn.execute("DELETE FROM reports")
            conn.executemany(
                "INSERT INTO reports (ip, time, severity) VALUES (?, ?, ?)",
                [(ip, v["time"], v["severity"]) for ip, v in cache.get("reports", {}).items()],
            )
            conn.execute("DELETE FROM pending")
            conn.executemany(
                "INSERT INTO pending (ip, due_time, severity, categories, comment) VALUES (?, ?, ?, ?, ?)",
                [(ip, v["due_time"], v["severity"], v["categories"], v["comment"])
                 for ip, v in cache.get("pending", {}).items()],
            )
            conn.execute("DELETE FROM retry_queue")
            conn.executemany(
                "INSERT INTO retry_queue (ip, due_time, categories, comment, attempts) VALUES (?, ?, ?, ?, ?)",
                [(ip, v["due_time"], v["categories"], v["comment"], v["attempts"])
                 for ip, v in cache.get("retry_queue", {}).items()],
            )
    finally:
        conn.close()


# AbuseIPDB returns X-RateLimit-Limit / X-RateLimit-Remaining on every
# report response (success or error), and resets at 00:00 UTC. Tracked
# here so it's visible via /health and /metrics without needing a
# separate call to check it — and so we can warn before actually running
# out mid-day. Also persisted to a small sidecar file next to the cache:
# quota_state itself is only in-memory, which is fine for /health and
# /metrics (same process), but --stats runs as a separate one-shot
# process and has no other way to see what the live service last saw.
quota_lock = threading.Lock()
quota_state = {"limit": None, "remaining": None, "updated_at": None}
_quota_warned_date = None  # UTC date string; reset naturally at the daily rollover

QUOTA_WARN_THRESHOLD = int(os.getenv("ABUSEIPDB_QUOTA_WARN_THRESHOLD", "50"))
QUOTA_STATE_FILE = CACHE_FILE + ".quota.json"

# --- Quota reservation --------------------------------------------------
# Without this, a burst of low-severity noise (port scans, bad bots) can
# burn through the daily quota before a genuine high-severity finding
# (SQLi, exploited host) shows up later the same day. Both default to 0
# (disabled — matches current behavior). Set ABUSEIPDB_QUOTA_RESERVE_HIGH
# to hold back that many of the day's remaining reports for severity-3
# only; ABUSEIPDB_QUOTA_RESERVE_MEDIUM likewise for severity 2 and up.
# Reservation only kicks in once the proxy has actually seen a remaining
# count from AbuseIPDB's own rate-limit headers (quota_state["remaining"]
# starts as None) — it never blocks anything based on a guess.
QUOTA_RESERVE_MEDIUM = int(os.getenv("ABUSEIPDB_QUOTA_RESERVE_MEDIUM", "0"))
QUOTA_RESERVE_HIGH = int(os.getenv("ABUSEIPDB_QUOTA_RESERVE_HIGH", "0"))


def quota_reserved_for(severity):
    """True if a report of this severity should be held back right now
    because the remaining daily quota is reserved for a higher tier."""
    with quota_lock:
        remaining = quota_state.get("remaining")
    if remaining is None:
        return False
    if severity < 3 and QUOTA_RESERVE_HIGH > 0 and remaining <= QUOTA_RESERVE_HIGH:
        return True
    if severity < 2 and QUOTA_RESERVE_MEDIUM > 0 and remaining <= QUOTA_RESERVE_MEDIUM:
        return True
    return False


def _save_quota_state():
    # Best-effort only: quota tracking is a nice-to-have observability
    # feature, never worth crashing (or even logging loudly) over if the
    # disk write fails — save_cache() already has real error handling
    # and alerting for actual cache-write failures, this doesn't need to
    # duplicate that for a small sidecar file.
    try:
        ensure_cache_dir()
        tmp_path = QUOTA_STATE_FILE + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(quota_state, f)
        os.replace(tmp_path, QUOTA_STATE_FILE)
    except OSError:
        pass


def load_quota_state():
    """Reads the persisted quota snapshot from disk — used by --stats,
    which runs as a separate process and can't see another process's
    in-memory quota_state directly."""
    try:
        with open(QUOTA_STATE_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {
                "limit": data.get("limit"),
                "remaining": data.get("remaining"),
                "updated_at": data.get("updated_at"),
            }
    except (OSError, json.JSONDecodeError):
        pass
    return {"limit": None, "remaining": None, "updated_at": None}


def _update_quota_from_headers(headers):
    if not headers:
        return
    limit = headers.get("X-RateLimit-Limit")
    remaining = headers.get("X-RateLimit-Remaining")
    if limit is None and remaining is None:
        return
    global _quota_warned_date
    should_notify = False
    with quota_lock:
        try:
            if limit is not None:
                quota_state["limit"] = int(limit)
            if remaining is not None:
                quota_state["remaining"] = int(remaining)
        except (TypeError, ValueError):
            return
        quota_state["updated_at"] = int(time.time())
        remaining_now = quota_state["remaining"]
        limit_now = quota_state["limit"]
        _save_quota_state()

        # Deciding *and* marking "already warned today" both happen while
        # still holding quota_lock — otherwise two concurrent report
        # threads could both see the old date, both flip it, and both
        # fire the notification.
        if remaining_now is not None and remaining_now <= QUOTA_WARN_THRESHOLD:
            today = datetime.now(timezone.utc).date().isoformat()
            if _quota_warned_date != today:
                _quota_warned_date = today
                should_notify = True

    if should_notify:
        log(f"AbuseIPDB daily quota is getting low: {remaining_now} report(s) remaining.",
            level="warning", quota_remaining=remaining_now, quota_limit=limit_now)
        notify(
            f"AbuseIPDB daily quota is getting low: only {remaining_now} report(s) remaining "
            f"today (limit {limit_now}). Resets at 00:00 UTC.",
            priority="normal",
        )


_whitelist_cache_lock = threading.Lock()
_whitelist_cache = {}  # ip -> (is_whitelisted, checked_at_epoch)


def is_whitelisted(ip):
    """Queries /v2/check for whether AbuseIPDB itself marks this IP as
    whitelisted. Result is cached in memory per IP for
    ABUSEIPDB_WHITELIST_CACHE_TTL seconds, so a fast-repeating IP doesn't
    burn a /v2/check call (and its own separate daily quota) on every
    single alert. Fails open (returns False, i.e. "report it") on any
    error — a network hiccup here must never block a legitimate report."""
    if not SKIP_WHITELISTED or DRY_RUN:
        return False

    now = time.time()
    with _whitelist_cache_lock:
        cached = _whitelist_cache.get(ip)
        if cached and now - cached[1] < WHITELIST_CACHE_TTL:
            return cached[0]

    url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip})
    req = urllib.request.Request(url, headers={"Key": _current_api_key(), "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        whitelisted = bool(data.get("data", {}).get("isWhitelisted"))
    except Exception as e:
        log(f"Whitelist check for {ip} failed, reporting anyway: {e}", level="warning", ip=ip)
        return False

    with _whitelist_cache_lock:
        _whitelist_cache[ip] = (whitelisted, now)
    return whitelisted


# --- Comment scrubbing -------------------------------------------------
# Off by default. AbuseIPDB comments are public — if your CrowdSec
# scenario/comment templates ever end up echoing something internal
# (a hostname, an internal path, a stack trace line), this strips it
# before the report leaves the box. Applied once, right before the
# actual API call, so it covers retries consistently without needing to
# be re-applied by every caller.
def _parse_scrub_patterns(raw):
    """ABUSEIPDB_COMMENT_SCRUB_PATTERNS is semicolon-separated (not comma
    — regexes routinely contain commas themselves, e.g. `{2,4}`)."""
    patterns = []
    for item in raw.split(";"):
        item = item.strip()
        if not item:
            continue
        try:
            patterns.append(re.compile(item))
        except re.error as e:
            log(f"Warning: invalid regex in ABUSEIPDB_COMMENT_SCRUB_PATTERNS: "
                f"'{item}' ({e}), skipping.", level="warning", pattern=item)
    return patterns


COMMENT_SCRUB_PATTERNS = _parse_scrub_patterns(os.getenv("ABUSEIPDB_COMMENT_SCRUB_PATTERNS", ""))
COMMENT_SCRUB_REPLACEMENT = os.getenv("ABUSEIPDB_COMMENT_SCRUB_REPLACEMENT", "[redacted]")


def scrub_comment(comment):
    if not COMMENT_SCRUB_PATTERNS or not comment:
        return comment
    for pattern in COMMENT_SCRUB_PATTERNS:
        comment = pattern.sub(COMMENT_SCRUB_REPLACEMENT, comment)
    return comment


# --- Fallback API key ----------------------------------------------------
# Off by default. If you run two AbuseIPDB accounts, this switches to a
# second key once the primary's daily report quota is exhausted, instead
# of just queuing everything for retry until midnight UTC. Switches back
# to the primary key the first time a new UTC day is seen — a fresh guess
# at "the primary's quota probably reset", not a guarantee (AbuseIPDB
# doesn't document the exact reset instant), so a stray 429 right after
# midnight just switches back to the fallback again.
API_KEY_FALLBACK = _get_secret("ABUSEIPDB_API_KEY_FALLBACK").strip()

_active_key_lock = threading.Lock()
_using_fallback_key = False
_fallback_switch_date = None


def _current_api_key():
    with _active_key_lock:
        return API_KEY_FALLBACK if _using_fallback_key else API_KEY


def _maybe_reset_fallback_key():
    global _using_fallback_key, _fallback_switch_date
    if not _using_fallback_key:
        return
    today = datetime.now(timezone.utc).date()
    with _active_key_lock:
        if _using_fallback_key and _fallback_switch_date and today > _fallback_switch_date:
            _using_fallback_key = False
            _fallback_switch_date = None
            log("New UTC day: switching back to the primary AbuseIPDB API key.", level="info")


def _switch_to_fallback_key(reason):
    """Returns True if it actually switched (i.e. a fallback key is
    configured and we weren't already using it) — the caller uses this to
    decide whether an immediate retry with the new key is worth it."""
    global _using_fallback_key, _fallback_switch_date
    if not API_KEY_FALLBACK:
        return False
    with _active_key_lock:
        if _using_fallback_key:
            return False  # already switched by another thread — nothing to do
        _using_fallback_key = True
        _fallback_switch_date = datetime.now(timezone.utc).date()
    log(f"Switching to fallback AbuseIPDB API key: {reason}", level="warning")
    notify(f"Switched to the fallback AbuseIPDB API key: {reason}", priority="normal")
    return True


def send_report_api(ip, categories, comment):
    """
    Attempts a single API call. Returns (success, retry_after_seconds).
    retry_after_seconds is taken from the response's Retry-After header
    when present (AbuseIPDB sends this on 429), otherwise None.
    """
    comment = scrub_comment(comment)

    if DRY_RUN:
        log(
            f"[dry-run] would report ip={ip} categories={categories} comment={comment!r}",
            ip=ip, categories=categories, dry_run=True,
        )
        return True, None

    _maybe_reset_fallback_key()

    def _attempt():
        url = "https://api.abuseipdb.com/api/v2/report"
        headers = {
            "Key": _current_api_key(),
            "Accept": "application/json"
        }
        params = urllib.parse.urlencode({
            "ip": ip,
            "categories": categories,
            "comment": comment
        }).encode('utf-8')

        req = urllib.request.Request(url, data=params, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
                _update_quota_from_headers(resp.headers)
            return True, None, None
        except urllib.error.HTTPError as e:
            retry_after = None
            try:
                ra = e.headers.get("Retry-After") if e.headers else None
                if ra:
                    retry_after = int(ra)
            except (TypeError, ValueError):
                retry_after = None
            _update_quota_from_headers(e.headers)
            log(f"Report for {ip} failed: HTTP {e.code}", level="warning", ip=ip, http_status=e.code)
            return False, retry_after, e.code
        except Exception as e:
            log(f"Report for {ip} failed: {e}", level="warning", ip=ip)
            return False, None, None

    success, retry_after, http_status = _attempt()
    if not success and http_status == 429:
        # A 429 on the *primary* key most likely means its daily quota is
        # exhausted — worth switching and retrying right away rather than
        # letting this sit in the retry queue for however long
        # Retry-After says (can be hours, for a daily-quota 429).
        if _switch_to_fallback_key(f"HTTP 429 while reporting {ip}"):
            success, retry_after, http_status = _attempt()
    return success, retry_after


def send_with_retry(ip, categories, comment, attempt=1):
    """
    Sends a report, retrying on failure (network errors, 5xx, or 429) up to
    MAX_RETRIES times. Retries are persisted to the cache's "retry_queue"
    so they survive a proxy restart. Does NOT touch the "reports" dedup
    entry — that's written optimistically by the caller before this runs.
    """
    success, retry_after = send_report_api(ip, categories, comment)

    if success:
        if not DRY_RUN and VERBOSE_LOGGING:
            log(f"Reported {ip} to AbuseIPDB (categories={categories}).", ip=ip, categories=categories)
        inc_metric("reports_sent_total")
        with lock:
            cache = load_cache()
            cache["retry_queue"].pop(ip, None)
            save_cache(cache)
        retry_timers.pop(ip, None)
        return

    if attempt >= MAX_RETRIES:
        log(f"Giving up on {ip} after {attempt} failed attempt(s).",
            level="error", ip=ip, attempts=attempt)
        inc_metric("reports_failed_total")
        notify(f"Gave up reporting {ip} to AbuseIPDB after {attempt} failed attempt(s). Check the logs for details.", priority="high")
        with lock:
            cache = load_cache()
            cache["retry_queue"].pop(ip, None)
            save_cache(cache)
        retry_timers.pop(ip, None)
        return

    delay = retry_after if retry_after else RETRY_DELAY
    now = int(time.time())
    retry_at_local = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now + delay))
    reason = "AbuseIPDB-provided Retry-After (likely a rate limit)" if retry_after else "default retry delay"
    log(
        f"Will retry {ip} at {retry_at_local} "
        f"(in {delay}s, {reason}), attempt {attempt + 1}/{MAX_RETRIES}.",
        level="warning", ip=ip, retry_at=retry_at_local, delay_seconds=delay,
        attempt=attempt + 1, max_retries=MAX_RETRIES,
    )
    with lock:
        cache = load_cache()
        cache["retry_queue"][ip] = {
            "due_time": now + delay,
            "categories": categories,
            "comment": comment,
            "attempts": attempt,
        }
        save_cache(cache)

    timer = threading.Timer(delay, send_with_retry, args=(ip, categories, comment, attempt + 1))
    timer.daemon = True
    retry_timers[ip] = timer
    timer.start()


def _finalize_pending(ip, categories, comment, new_severity):
    """Runs when a delayed (escalation) report is due: records it in
    "reports" (dedup, optimistic) and hands delivery off to the retry-aware
    sender. Quota reservation is re-checked here too — the remaining quota
    seen when this was scheduled may not hold by the time it actually
    fires, potentially minutes or hours later."""
    t_now = int(time.time())
    with lock:
        cache = load_cache()
        pending_timers.pop(ip, None)
        if quota_reserved_for(new_severity):
            cache["pending"].pop(ip, None)
            save_cache(cache)
            inc_metric("reports_quota_reserved_total")
            if VERBOSE_LOGGING:
                log(f"Dropping due escalation for {ip} (severity {new_severity}): "
                    f"daily quota reserved for a higher severity tier.",
                    ip=ip, severity=new_severity)
            return
        cache["reports"][ip] = {"time": t_now, "severity": new_severity}
        cache["pending"].pop(ip, None)
        save_cache(cache)
    threading.Thread(target=send_with_retry, args=(ip, categories, comment), daemon=True).start()


def _schedule_pending(ip, categories, comment, new_severity, delay):
    """Schedules (or re-schedules) a delayed escalation report and persists
    it, so a proxy restart can pick it back up instead of silently
    dropping it. Acquires `lock` itself (it's an RLock, so this is safe
    even when — as today — the only caller already holds it) rather than
    relying on every future caller to remember to hold it first."""
    with lock:
        timer = threading.Timer(delay, _finalize_pending, args=(ip, categories, comment, new_severity))
        timer.daemon = True
        pending_timers[ip] = {"timer": timer, "severity": new_severity}
        timer.start()

        now = int(time.time())
        cache = load_cache()
        cache["pending"][ip] = {
            "due_time": now + delay,
            "severity": new_severity,
            "categories": categories,
            "comment": comment,
        }
        save_cache(cache)


def process_alert(ip, categories, comment, new_severity):
    """Returns the background Thread actually sending the report, if one
    was started (None if suppressed/reserved/pending/deduped) — most
    callers (the live HTTP path) fire-and-forget and ignore this; --reconcile
    uses it to wait for its batch of catch-up sends before the process exits."""
    now = int(time.time())
    with lock:
        cache = load_cache()
        cache["reports"] = {
            k: v for k, v in cache["reports"].items() if v.get("time", 0) > now - 86400
        }

        entry = cache["reports"].get(ip)

        if not entry:
            if ip in pending_timers:
                pending_timers[ip]["timer"].cancel()
                del pending_timers[ip]
                cache["pending"].pop(ip, None)

            if quota_reserved_for(new_severity):
                save_cache(cache)  # persist the pruned "reports" map either way
                inc_metric("reports_quota_reserved_total")
                if VERBOSE_LOGGING:
                    log(f"Holding back report for {ip} (severity {new_severity}): "
                        f"daily quota reserved for a higher severity tier.",
                        ip=ip, severity=new_severity)
                return

            cache["reports"][ip] = {"time": now, "severity": new_severity}
            save_cache(cache)
            t = threading.Thread(target=send_with_retry, args=(ip, categories, comment), daemon=True)
            t.start()
            return t

        last_time = entry.get("time", 0)
        last_severity = entry.get("severity", 1)
        time_passed = now - last_time

        if new_severity > last_severity:
            pending = pending_timers.get(ip)
            pending_sev = pending["severity"] if pending else 0

            if new_severity > pending_sev:
                if pending:
                    pending["timer"].cancel()
                    del pending_timers[ip]
                    cache["pending"].pop(ip, None)

                window = get_report_window(new_severity, categories)
                if time_passed >= window:
                    if quota_reserved_for(new_severity):
                        save_cache(cache)
                        inc_metric("reports_quota_reserved_total")
                        if VERBOSE_LOGGING:
                            log(f"Holding back escalation for {ip} (severity {new_severity}): "
                                f"daily quota reserved for a higher severity tier.",
                                ip=ip, severity=new_severity)
                        return
                    cache["reports"][ip] = {"time": now, "severity": new_severity}
                    save_cache(cache)
                    t = threading.Thread(target=send_with_retry, args=(ip, categories, comment), daemon=True)
                    t.start()
                    return t
                else:
                    delay = window - time_passed
                    save_cache(cache)  # persist the pruned "reports" map first
                    _schedule_pending(ip, categories, comment, new_severity, delay)
            else:
                inc_metric("reports_suppressed_total")  # escalation already pending at >= this severity
        else:
            inc_metric("reports_suppressed_total")  # same or lower severity within the window


def resume_state_from_cache():
    """Called once at startup. Re-arms any delayed escalation reports and
    any queued retries that were still outstanding when the proxy was last
    stopped/restarted, instead of silently losing them."""
    now = int(time.time())
    with lock:
        cache = load_cache()
        pending = cache.get("pending", {})
        retry_queue = cache.get("retry_queue", {})

        resumed_pending = 0
        for ip, info in list(pending.items()):
            delay = max(0, info.get("due_time", now) - now)
            timer = threading.Timer(
                delay, _finalize_pending,
                args=(ip, info.get("categories", "15"), info.get("comment", "CrowdSec Alert"), info.get("severity", 1))
            )
            timer.daemon = True
            pending_timers[ip] = {"timer": timer, "severity": info.get("severity", 1)}
            timer.start()
            resumed_pending += 1

        resumed_retries = 0
        for ip, info in list(retry_queue.items()):
            delay = max(0, info.get("due_time", now) - now)
            attempt = info.get("attempts", 1)
            timer = threading.Timer(
                delay, send_with_retry,
                args=(ip, info.get("categories", "15"), info.get("comment", "CrowdSec Alert"), attempt)
            )
            timer.daemon = True
            retry_timers[ip] = timer
            timer.start()
            resumed_retries += 1

        if resumed_pending:
            log(f"Resumed {resumed_pending} pending escalation report(s) from cache.", pending_count=resumed_pending)
        if resumed_retries:
            log(f"Resumed {resumed_retries} queued retry/retries from cache.", retry_count=resumed_retries)


class AbuseIPDBHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        client_ip = self.client_address[0]
        if not is_source_ip_allowed(client_ip):
            log(f"Rejected POST from disallowed source {client_ip}.",
                level="warning", source_ip=client_ip)
            self.send_response(403)
            self.end_headers()
            return
        if not is_shared_secret_valid(self.headers.get("X-Proxy-Secret")):
            log(f"Rejected POST from {client_ip}: missing or invalid X-Proxy-Secret.",
                level="warning", source_ip=client_ip)
            self.send_response(403)
            self.end_headers()
            return

        if _request_semaphore is not None and not _request_semaphore.acquire(blocking=False):
            log(f"Rejected POST from {client_ip}: at ABUSEIPDB_MAX_CONCURRENT_REQUESTS "
                f"limit ({MAX_CONCURRENT_REQUESTS}).", level="warning", source_ip=client_ip)
            inc_metric("reports_rejected_overload_total")
            self.send_response(503)
            self.send_header("Retry-After", "1")
            self.end_headers()
            return
        try:
            self._handle_post()
        finally:
            if _request_semaphore is not None:
                _request_semaphore.release()

    def _handle_post(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode('utf-8'))
            ip = data.get("ip")
            categories = data.get("categories", "15").strip()
            comment = data.get("comment", "CrowdSec Alert")

            if ip:
                if is_ignored_ip(ip):
                    if VERBOSE_LOGGING:
                        log(f"Ignoring private/excluded IP {ip}.", ip=ip)
                    inc_metric("reports_ignored_private_total")
                elif is_whitelisted(ip):
                    if VERBOSE_LOGGING:
                        log(f"Skipping AbuseIPDB-whitelisted IP {ip}.", ip=ip)
                    inc_metric("reports_whitelisted_total")
                else:
                    severity = get_severity(categories)
                    process_alert(ip, categories, comment, severity)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode('utf-8'))

    def do_GET(self):
        if self.path in ("/health", "/status"):
            if ENABLE_HEALTH:
                self._handle_health()
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path == "/metrics":
            if ENABLE_METRICS:
                self._handle_metrics()
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_health(self):
        with lock:
            cache = load_cache()
        with quota_lock:
            quota = dict(quota_state)
        body = json.dumps({
            "status": "ok",
            "version": VERSION,
            "dry_run": DRY_RUN,
            "uptime_seconds": int(time.time() - START_TIME),
            "cache_reports_tracked": len(cache.get("reports", {})),
            "pending_escalations": len(pending_timers),
            "pending_retries": len(retry_timers),
            "abuseipdb_quota": quota,
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_metrics(self):
        with metrics_lock:
            snapshot = dict(metrics)

        lines = []

        def counter(name, help_text, value):
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")

        def gauge(name, help_text, value):
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")

        counter("abuseipdb_proxy_reports_sent_total", "Total reports successfully sent to AbuseIPDB.",
                 snapshot.get("reports_sent_total", 0))
        counter("abuseipdb_proxy_reports_suppressed_total", "Total alerts suppressed by dedup/escalation logic.",
                 snapshot.get("reports_suppressed_total", 0))
        counter("abuseipdb_proxy_reports_failed_total", "Total reports that permanently failed after all retries.",
                 snapshot.get("reports_failed_total", 0))
        counter("abuseipdb_proxy_reports_ignored_private_total", "Total alerts ignored because the IP was private/reserved.",
                 snapshot.get("reports_ignored_private_total", 0))
        counter("abuseipdb_proxy_reports_quota_reserved_total",
                 "Total reports held back because the remaining daily quota was reserved for a higher severity tier.",
                 snapshot.get("reports_quota_reserved_total", 0))
        counter("abuseipdb_proxy_reports_whitelisted_total",
                 "Total alerts skipped because AbuseIPDB itself marks the IP as whitelisted.",
                 snapshot.get("reports_whitelisted_total", 0))
        counter("abuseipdb_proxy_reports_rejected_overload_total",
                 "Total POSTs rejected with 503 because ABUSEIPDB_MAX_CONCURRENT_REQUESTS was reached.",
                 snapshot.get("reports_rejected_overload_total", 0))
        gauge("abuseipdb_proxy_pending_escalations", "Current number of delayed escalation reports awaiting delivery.",
              len(pending_timers))
        gauge("abuseipdb_proxy_pending_retries", "Current number of reports queued for retry.",
              len(retry_timers))
        gauge("abuseipdb_proxy_uptime_seconds", "Seconds since the proxy started.",
              int(time.time() - START_TIME))
        if API_KEY_FALLBACK:
            gauge("abuseipdb_proxy_using_fallback_key", "1 if currently reporting with the fallback API key, 0 if using the primary.",
                  1 if _using_fallback_key else 0)

        with quota_lock:
            quota = dict(quota_state)
        if quota["remaining"] is not None:
            gauge("abuseipdb_proxy_quota_remaining", "AbuseIPDB reports remaining today (resets 00:00 UTC).",
                  quota["remaining"])
        if quota["limit"] is not None:
            gauge("abuseipdb_proxy_quota_limit", "AbuseIPDB daily report limit for this API key/tier.",
                  quota["limit"])

        lines.append(f"# HELP abuseipdb_proxy_info Static build info, value is always 1.")
        lines.append(f"# TYPE abuseipdb_proxy_info gauge")
        lines.append(f'abuseipdb_proxy_info{{version="{VERSION}"}} 1')

        body = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


EXPORT_FORMAT = "abuseipdb-proxy-cache-export"
EXPORT_FORMAT_VERSION = 1


def export_cache_json():
    """Portable, backend-agnostic snapshot of the current cache (works the
    same whether the active backend is JSON or SQLite) — for backups or
    moving the report history to a different host."""
    with lock:
        cache = load_cache()
    return json.dumps({
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "proxy_version": VERSION,
        "cache_backend": CACHE_BACKEND,
        "cache": cache,
    }, indent=2)


def import_cache_json(raw_json):
    """
    Parses and validates a snapshot produced by export_cache_json().
    Returns the {"reports", "pending", "retry_queue"} dict ready to pass
    to save_cache(). Raises ValueError with a clear message on anything
    malformed, rather than silently importing garbage into the cache.
    """
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"not valid JSON: {e}")

    if not isinstance(data, dict) or data.get("format") != EXPORT_FORMAT:
        raise ValueError(
            f"not a recognized cache export (expected \"format\": \"{EXPORT_FORMAT}\")"
        )

    cache = data.get("cache")
    if not isinstance(cache, dict) or not all(k in cache for k in ("reports", "pending", "retry_queue")):
        raise ValueError("export is missing one of reports/pending/retry_queue")

    return {
        "reports": cache.get("reports") or {},
        "pending": cache.get("pending") or {},
        "retry_queue": cache.get("retry_queue") or {},
    }


def vacuum_cache():
    """
    Prunes reports past the escalation-relevant window (the same rule
    process_alert() already applies lazily whenever a new alert comes
    in) and then VACUUMs the SQLite file to reclaim the space freed by
    that prune, plus space fragmented by the continuous DELETE+INSERT
    churn every save_cache() call does under the hood. Safe to run
    anytime; a no-op (with a clear message, not an error) on the JSON
    backend, since VACUUM is a SQLite-specific concept.
    """
    if CACHE_BACKEND != "sqlite":
        log(f"--vacuum only applies to the SQLite cache backend (current backend: {CACHE_BACKEND}). "
            "Nothing to do.")
        return None

    size_before = os.path.getsize(CACHE_FILE) if os.path.exists(CACHE_FILE) else 0

    with lock:
        cache = load_cache()
        now = int(time.time())
        before_count = len(cache["reports"])
        cache["reports"] = {k: v for k, v in cache["reports"].items() if v.get("time", 0) > now - 86400}
        pruned = before_count - len(cache["reports"])
        save_cache(cache)

    conn = sqlite3.connect(CACHE_FILE, timeout=10, isolation_level=None)  # autocommit: VACUUM needs no open transaction
    try:
        conn.execute("VACUUM")
    finally:
        conn.close()

    size_after = os.path.getsize(CACHE_FILE) if os.path.exists(CACHE_FILE) else 0
    log(
        f"Vacuumed SQLite cache: pruned {pruned} stale report(s), "
        f"file size {size_before} -> {size_after} bytes.",
        pruned=pruned, size_before=size_before, size_after=size_after,
    )
    return {"pruned": pruned, "size_before": size_before, "size_after": size_after}


def _human_ago(epoch_seconds, now=None):
    now = now if now is not None else time.time()
    delta = max(0, int(now - epoch_seconds))
    if delta < 60:
        return "just now" if delta < 5 else f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _human_in(epoch_seconds, now=None):
    now = now if now is not None else time.time()
    delta = int(epoch_seconds - now)
    if delta <= 0:
        return "due now"
    if delta < 3600:
        return f"in {delta // 60}m {delta % 60}s"
    return f"in {delta // 3600}h {(delta % 3600) // 60}m"


def build_stats(limit=10):
    """
    A snapshot of what's currently in the cache: recent reports (with a
    severity breakdown), pending escalations, queued retries, and the
    AbuseIPDB quota — read directly from the cache, so this works
    identically whether it's called from the running service or as a
    one-off `--stats` invocation against the same cache file/database.
    Note this only reflects what's persisted in the cache, not the
    in-process metrics counters (reports_sent_total etc.) of a
    *different*, currently-running process — see /metrics for those.
    """
    now = time.time()
    with lock:
        cache = load_cache()

    reports = cache.get("reports", {})
    severity_counts = {1: 0, 2: 0, 3: 0}
    for entry in reports.values():
        sev = entry.get("severity", 1)
        if sev in severity_counts:
            severity_counts[sev] += 1

    recent = sorted(reports.items(), key=lambda kv: kv[1].get("time", 0), reverse=True)[:limit]

    pending = sorted(cache.get("pending", {}).items(), key=lambda kv: kv[1].get("due_time", 0))
    retries = sorted(cache.get("retry_queue", {}).items(), key=lambda kv: kv[1].get("due_time", 0))

    quota = load_quota_state()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cache_backend": CACHE_BACKEND,
        "cache_file": CACHE_FILE,
        "reports_tracked": len(reports),
        "reports_by_severity": {"low": severity_counts[1], "medium": severity_counts[2], "high": severity_counts[3]},
        "recent_reports": [
            {"ip": ip, "time": v.get("time"), "severity": v.get("severity")}
            for ip, v in recent
        ],
        "pending_escalations": [
            {"ip": ip, "due_time": v.get("due_time"), "severity": v.get("severity"), "categories": v.get("categories")}
            for ip, v in pending
        ],
        "queued_retries": [
            {"ip": ip, "due_time": v.get("due_time"), "attempts": v.get("attempts")}
            for ip, v in retries
        ],
        "abuseipdb_quota": quota,
    }


_SEVERITY_NAMES = {1: "low", 2: "medium", 3: "high"}


def format_stats_text(stats, now=None):
    now = now if now is not None else time.time()
    lines = []
    lines.append("=== CrowdSec Smart AbuseIPDB Proxy — Cache Stats ===")
    lines.append(f"Backend: {stats['cache_backend']} ({stats['cache_file']})")
    lines.append("")
    lines.append(f"Reports tracked (last 24h): {stats['reports_tracked']}")
    by_sev = stats["reports_by_severity"]
    lines.append(f"  by severity: low={by_sev['low']} medium={by_sev['medium']} high={by_sev['high']}")
    lines.append("")

    if stats["recent_reports"]:
        lines.append("Most recently reported IPs:")
        for r in stats["recent_reports"]:
            sev_name = _SEVERITY_NAMES.get(r["severity"], "?")
            lines.append(f"  {r['ip']:<16} {sev_name:<7} {_human_ago(r['time'], now)}")
    else:
        lines.append("No reports currently tracked.")
    lines.append("")

    if stats["pending_escalations"]:
        lines.append(f"Pending escalations: {len(stats['pending_escalations'])}")
        for p in stats["pending_escalations"]:
            sev_name = _SEVERITY_NAMES.get(p["severity"], "?")
            lines.append(f"  {p['ip']:<16} {_human_in(p['due_time'], now):<14} severity={sev_name}")
    else:
        lines.append("Pending escalations: none")
    lines.append("")

    if stats["queued_retries"]:
        lines.append(f"Queued retries: {len(stats['queued_retries'])}")
        for r in stats["queued_retries"]:
            lines.append(f"  {r['ip']:<16} {_human_in(r['due_time'], now):<14} attempt {r['attempts']}/{MAX_RETRIES}")
    else:
        lines.append("Queued retries: none")
    lines.append("")

    quota = stats["abuseipdb_quota"]
    if quota["remaining"] is not None:
        as_of = f" (as of {_human_ago(quota['updated_at'], now)})" if quota["updated_at"] else ""
        lines.append(f"AbuseIPDB quota: {quota['remaining']}/{quota['limit']} remaining{as_of}")
    else:
        lines.append("AbuseIPDB quota: unknown (no report sent yet since the last quota reset)")

    return "\n".join(lines)


REPO_URL = "https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy"


def _configured_alerting_backends():
    names = []
    if GOTIFY_URL and GOTIFY_TOKEN:
        names.append("Gotify")
    if NTFY_URL:
        names.append("ntfy")
    if WEBHOOK_URL:
        names.append("webhook")
    if SLACK_WEBHOOK_URL:
        names.append("Slack")
    if DISCORD_WEBHOOK_URL:
        names.append("Discord")
    if MATRIX_HOMESERVER_URL and MATRIX_ACCESS_TOKEN and MATRIX_ROOM_ID:
        names.append("Matrix")
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        names.append("Telegram")
    if HOMEASSISTANT_URL and HOMEASSISTANT_TOKEN:
        names.append("Home Assistant")
    return ", ".join(names) if names else "none configured"


def format_startup_banner():
    """
    A boxed startup summary: a quick, at-a-glance summary of
    what's actually running and how it's configured, right where
    `docker logs`/`journalctl` show it first — version, mode, cache
    backend, listen address, which alerting backends are active.
    """
    title = f"CrowdSec Smart AbuseIPDB Proxy v{VERSION}"
    info_rows = [
        f"Mode          : {'dry-run' if DRY_RUN else 'live'}",
        f"Cache backend : {CACHE_BACKEND} ({CACHE_FILE})",
        f"Listening on  : {LISTEN_ADDRESS}:{LISTEN_PORT}",
        f"Alerting      : {_configured_alerting_backends()}",
    ]
    width = max(len(title), max(len(r) for r in info_rows), len(REPO_URL)) + 2

    lines = ["/" + "-" * (width + 2) + "\\"]
    lines.append("| " + title.center(width) + " |")
    lines.append("|" + "-" * (width + 2) + "|")
    for row in info_rows:
        lines.append("| " + row.ljust(width) + " |")
    lines.append("|" + "-" * (width + 2) + "|")
    lines.append("| " + REPO_URL.center(width) + " |")
    lines.append("\\" + "-" * (width + 2) + "/")
    return "\n".join(lines)


def print_startup_banner():
    # A decorative ASCII box has no sensible structured-log
    # representation, so it's skipped entirely in JSON log mode rather
    # than mangled into one — the version/mode/backend/etc. it shows are
    # all separately available via --stats or /health anyway.
    if LOG_FORMAT != "json":
        sys.stderr.write(format_startup_banner() + "\n")


def check_config():
    """
    Validates the current configuration end-to-end and returns a list of
    (level, message) tuples — level is "ok", "warn", or "fail". Doesn't
    touch the network; catches the kind of mistakes that would otherwise
    only surface later as a silently-failed report or notification (a
    typo'd env var name, a backend missing half its required settings,
    an unwritable cache path, ...).
    """
    results = []

    def ok(msg):
        results.append(("ok", msg))

    def warn(msg):
        results.append(("warn", msg))

    def fail(msg):
        results.append(("fail", msg))

    # --- API key ---
    if DRY_RUN:
        ok("ABUSEIPDB_API_KEY not required (--dry-run / ABUSEIPDB_DRY_RUN active)")
    elif not API_KEY:
        fail("ABUSEIPDB_API_KEY is not set (required unless --dry-run)")
    elif len(API_KEY.strip()) < 20 or " " in API_KEY:
        warn("ABUSEIPDB_API_KEY looks unusually short or contains whitespace — double-check it")
    else:
        ok("ABUSEIPDB_API_KEY is set" + (" (from ABUSEIPDB_API_KEY_FILE)" if os.getenv("ABUSEIPDB_API_KEY_FILE", "").strip() else ""))

    # --- Cache ---
    if CACHE_BACKEND not in ("json", "sqlite"):
        fail(f"ABUSEIPDB_CACHE_BACKEND={CACHE_BACKEND!r} is invalid (must be 'json' or 'sqlite')")
    elif CACHE_BACKEND == "json":
        warn(f"Cache backend: json ({CACHE_FILE}) — deprecated, will be removed in 3.0.0. "
             f"Run 'abuseipdb_proxy.py --migrate-to-sqlite' to switch, then set "
             f"ABUSEIPDB_CACHE_BACKEND=sqlite.")
    else:
        ok(f"Cache backend: {CACHE_BACKEND} ({CACHE_FILE})")
    try:
        ensure_cache_dir()
        cache_dir = os.path.dirname(CACHE_FILE) or "."
        if os.access(cache_dir, os.W_OK):
            ok(f"Cache directory is writable: {cache_dir}")
        else:
            fail(f"Cache directory is not writable: {cache_dir}")
    except OSError as e:
        fail(f"Cache directory could not be created: {e}")
    if CACHE_BACKEND == "sqlite":
        ok(f"SQLite pragmas: journal_mode={CACHE_SQLITE_JOURNAL_MODE}, synchronous={CACHE_SQLITE_SYNCHRONOUS}")

    # --- Networking ---
    if not (1 <= LISTEN_PORT <= 65535):
        fail(f"ABUSEIPDB_PROXY_PORT={LISTEN_PORT} is out of range (1-65535)")
    else:
        ok(f"Listening on {LISTEN_ADDRESS}:{LISTEN_PORT}")
    if LISTEN_ADDRESS not in ("127.0.0.1", "localhost") and not DRY_RUN:
        if ALLOWED_SOURCE_NETWORKS or SHARED_SECRET:
            ok(f"ABUSEIPDB_LISTEN_ADDRESS={LISTEN_ADDRESS!r}, but ABUSEIPDB_ALLOWED_SOURCE_IPS "
               f"and/or ABUSEIPDB_SHARED_SECRET is set as an extra layer of protection")
        else:
            warn(f"ABUSEIPDB_LISTEN_ADDRESS={LISTEN_ADDRESS!r} — make sure this is only reachable "
                 f"from a trusted network (e.g. inside Docker's own network isolation); consider "
                 f"ABUSEIPDB_ALLOWED_SOURCE_IPS / ABUSEIPDB_SHARED_SECRET for defense-in-depth")
    if ALLOWED_SOURCE_IPS and not ALLOWED_SOURCE_NETWORKS:
        fail("ABUSEIPDB_ALLOWED_SOURCE_IPS is set but none of its entries could be parsed as an IP/CIDR")
    elif ALLOWED_SOURCE_NETWORKS:
        ok(f"Source-IP allowlist active: {len(ALLOWED_SOURCE_NETWORKS)} network(s)")
    if SHARED_SECRET and len(SHARED_SECRET) < 16:
        warn("ABUSEIPDB_SHARED_SECRET is set but shorter than 16 characters — consider a longer value")
    if MAX_CONCURRENT_REQUESTS < 0:
        fail(f"ABUSEIPDB_MAX_CONCURRENT_REQUESTS={MAX_CONCURRENT_REQUESTS} is invalid (must be >= 0; 0 disables the limit)")
    elif MAX_CONCURRENT_REQUESTS == 0:
        warn("ABUSEIPDB_MAX_CONCURRENT_REQUESTS=0 — no ceiling on concurrent in-flight requests; "
             "a misconfiguration or bug feeding it a flood of decisions could spin up an unbounded "
             "number of threads")
    else:
        ok(f"Concurrent request ceiling: {MAX_CONCURRENT_REQUESTS}")

    # --- Quota reservation ---
    if QUOTA_RESERVE_HIGH and QUOTA_RESERVE_MEDIUM and QUOTA_RESERVE_MEDIUM < QUOTA_RESERVE_HIGH:
        warn(f"ABUSEIPDB_QUOTA_RESERVE_MEDIUM ({QUOTA_RESERVE_MEDIUM}) is smaller than "
             f"ABUSEIPDB_QUOTA_RESERVE_HIGH ({QUOTA_RESERVE_HIGH}) — the medium reserve should "
             f"normally be >= the high reserve, since it also covers severity 2")
    elif QUOTA_RESERVE_HIGH or QUOTA_RESERVE_MEDIUM:
        ok(f"Quota reservation active: {QUOTA_RESERVE_HIGH} reserved for high, "
           f"{QUOTA_RESERVE_MEDIUM} reserved for medium+")

    # --- Whitelist pre-check ---
    if SKIP_WHITELISTED and DRY_RUN:
        warn("ABUSEIPDB_SKIP_WHITELISTED is set but has no effect in --dry-run mode")
    elif SKIP_WHITELISTED:
        ok(f"AbuseIPDB whitelist pre-check active (cache TTL {WHITELIST_CACHE_TTL}s) — "
           f"uses its own separate /v2/check quota")

    # --- Comment scrubbing ---
    if os.getenv("ABUSEIPDB_COMMENT_SCRUB_PATTERNS", "").strip() and not COMMENT_SCRUB_PATTERNS:
        fail("ABUSEIPDB_COMMENT_SCRUB_PATTERNS is set but none of its entries could be parsed "
             "as valid regexes (semicolon-separated)")
    elif COMMENT_SCRUB_PATTERNS:
        ok(f"Comment scrubbing active: {len(COMMENT_SCRUB_PATTERNS)} pattern(s)")

    # --- Fallback API key ---
    if API_KEY_FALLBACK and API_KEY_FALLBACK == API_KEY:
        warn("ABUSEIPDB_API_KEY_FALLBACK is identical to ABUSEIPDB_API_KEY — "
             "switching to it won't help once the primary's quota is exhausted")
    elif API_KEY_FALLBACK:
        ok("Fallback API key configured")

    # --- Reconciliation ---
    if CROWDSEC_BOUNCER_KEY:
        ok(f"Reconciliation configured against CrowdSec LAPI at {CROWDSEC_LAPI_URL} "
           f"(run with --reconcile)")

    # --- Timing / retries ---
    window_low, window_medium, window_high = REPORT_WINDOWS[1], REPORT_WINDOWS[2], REPORT_WINDOWS[3]
    for name, value in (("ABUSEIPDB_REPORT_WINDOW_LOW", window_low),
                         ("ABUSEIPDB_REPORT_WINDOW_MEDIUM", window_medium),
                         ("ABUSEIPDB_REPORT_WINDOW_HIGH", window_high)):
        if value <= 0:
            fail(f"{name}={value} must be positive")
    if window_low <= window_medium <= window_high:
        ok(f"Report windows: low={window_low}s medium={window_medium}s high={window_high}s")
    else:
        warn("Report windows aren't in low <= medium <= high order — escalation timing may not "
             "behave as expected")
    if MAX_RETRIES < 1:
        fail(f"ABUSEIPDB_MAX_RETRIES={MAX_RETRIES} must be at least 1")
    else:
        ok(f"Retries: up to {MAX_RETRIES}, {RETRY_DELAY}s apart")

    # --- Alerting backends: each is either fully configured or fully
    # absent; anything in between is almost certainly a typo, since it
    # means that backend will just silently never fire. ---
    backend_checks = [
        ("Gotify", (GOTIFY_URL, GOTIFY_TOKEN), ("ABUSEIPDB_GOTIFY_URL", "ABUSEIPDB_GOTIFY_TOKEN")),
        ("Matrix", (MATRIX_HOMESERVER_URL, MATRIX_ACCESS_TOKEN, MATRIX_ROOM_ID),
         ("ABUSEIPDB_MATRIX_HOMESERVER_URL", "ABUSEIPDB_MATRIX_ACCESS_TOKEN", "ABUSEIPDB_MATRIX_ROOM_ID")),
        ("Telegram", (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID),
         ("ABUSEIPDB_TELEGRAM_BOT_TOKEN", "ABUSEIPDB_TELEGRAM_CHAT_ID")),
        ("Home Assistant", (HOMEASSISTANT_URL, HOMEASSISTANT_TOKEN),
         ("ABUSEIPDB_HOMEASSISTANT_URL", "ABUSEIPDB_HOMEASSISTANT_TOKEN")),
    ]
    any_backend_configured = bool(
        (GOTIFY_URL and GOTIFY_TOKEN) or NTFY_URL or WEBHOOK_URL or SLACK_WEBHOOK_URL
        or DISCORD_WEBHOOK_URL or (MATRIX_HOMESERVER_URL and MATRIX_ACCESS_TOKEN and MATRIX_ROOM_ID)
        or (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or (HOMEASSISTANT_URL and HOMEASSISTANT_TOKEN)
    )
    for name, values, var_names in backend_checks:
        set_count = sum(1 for v in values if v)
        if set_count == 0:
            continue  # fully absent, nothing to say
        if set_count == len(values):
            ok(f"{name} alerting backend is configured")
        else:
            fail(f"{name} alerting backend is partially configured — needs all of {', '.join(var_names)}, "
                 f"currently has {set_count}/{len(var_names)}. It will never actually send anything like this.")
    for name, url in (("ntfy", NTFY_URL), ("Slack", SLACK_WEBHOOK_URL),
                       ("Discord", DISCORD_WEBHOOK_URL), ("generic webhook", WEBHOOK_URL)):
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                ok(f"{name} alerting backend is configured")
            else:
                fail(f"{name} alerting backend URL doesn't look valid: {url!r}")
    if not any_backend_configured:
        warn("No alerting backend configured — you won't be notified of failures, low quota, "
             "or available updates. See \"Alerting\" in the README if that's not intentional.")

    return results


def format_config_check(results):
    symbols = {"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]"}
    lines = [f"{symbols[level]} {msg}" for level, msg in results]
    fail_count = sum(1 for level, _ in results if level == "fail")
    warn_count = sum(1 for level, _ in results if level == "warn")
    lines.append("")
    if fail_count:
        lines.append(f"{fail_count} problem(s), {warn_count} warning(s) — fix the [FAIL] items above.")
    elif warn_count:
        lines.append(f"No problems, {warn_count} warning(s) to review.")
    else:
        lines.append("All checks passed.")
    return "\n".join(lines)


def _run_systemctl(*args):
    """Returns (returncode, stdout) or (None, None) if systemctl isn't
    available at all — a non-systemd host, or (most commonly) inside a
    Docker container, where these checks just don't apply."""
    try:
        result = subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=5)
        return result.returncode, result.stdout.strip()
    except (FileNotFoundError, OSError):
        return None, None


def run_doctor(check_network=True):
    """
    A broader operational health check than --check-config: everything
    that covers, plus systemd service status, file permissions on the
    key/cache, whether CrowdSec's profiles.yaml actually wires this
    notification up, whether the cache is actually readable right now,
    and (optionally) whether api.abuseipdb.com is reachable at all. Bare
    -metal-specific checks (systemd, /etc/crowdsec/...) skip themselves
    cleanly rather than failing when they don't apply, e.g. in Docker.
    Meant to be run by a human troubleshooting something, not on every
    startup — unlike --check-config, this does touch the network and the
    filesystem beyond just the cache.
    """
    results = list(check_config())

    def ok(msg):
        results.append(("ok", msg))

    def warn(msg):
        results.append(("warn", msg))

    def fail(msg):
        results.append(("fail", msg))

    def skip(msg):
        results.append(("skip", msg))

    # --- systemd service ---
    rc, active = _run_systemctl("is-active", "abuseipdb-proxy.service")
    if rc is None:
        skip("systemd not available (expected in Docker/non-systemd hosts) — service status not checked")
    else:
        if active == "active":
            ok("systemd service abuseipdb-proxy.service is active")
        else:
            warn(f"systemd service abuseipdb-proxy.service is not active (state: {active or 'unknown'})")
        _, enabled = _run_systemctl("is-enabled", "abuseipdb-proxy.service")
        if enabled == "enabled":
            ok("systemd service is enabled (will start on boot)")
        else:
            warn(f"systemd service is not enabled (state: {enabled or 'unknown'}) — won't start on boot")

    # --- file permissions ---
    env_path = "/etc/abuseipdb-proxy/abuseipdb-proxy.env"
    if os.path.exists(env_path):
        mode = stat.S_IMODE(os.stat(env_path).st_mode)
        if mode & 0o077:
            warn(f"{env_path} is more permissive than 600 (it contains your API key) — chmod 600 recommended")
        else:
            ok(f"{env_path} permissions look fine (600)")
    else:
        skip(f"{env_path} not found — not a bare-metal install via install.sh, or different ABUSEIPDB_ prefix location")

    cache_dir = os.path.dirname(CACHE_FILE) or "."
    if os.path.isdir(cache_dir):
        mode = stat.S_IMODE(os.stat(cache_dir).st_mode)
        if mode & 0o077:
            warn(f"Cache directory {cache_dir} is more permissive than 700 recommended")
        else:
            ok(f"Cache directory {cache_dir} permissions look fine (700)")

    # --- CrowdSec wiring ---
    notif_path = "/etc/crowdsec/notifications/abuseipdb.yaml"
    if os.path.exists(notif_path):
        ok(f"CrowdSec notification config found: {notif_path}")
    else:
        skip(f"{notif_path} not found — not a bare-metal install via install.sh, or different host")

    profiles_path = "/etc/crowdsec/profiles.yaml"
    if os.path.exists(profiles_path):
        try:
            with open(profiles_path) as f:
                content = f.read()
            if "abuseipdb_default" in content:
                ok("abuseipdb_default is referenced in CrowdSec's profiles.yaml")
            else:
                warn("abuseipdb_default is NOT referenced in profiles.yaml — CrowdSec won't actually "
                     "trigger this notification. install.sh normally flags this for you to fix by hand.")
        except OSError as e:
            warn(f"Could not read {profiles_path}: {e}")
    else:
        skip(f"{profiles_path} not found")

    # --- cache reachability ---
    try:
        cache = load_cache()
        ok(f"Cache is readable ({len(cache.get('reports', {}))} report(s) currently tracked)")
    except Exception as e:
        fail(f"Cache could not be read: {e}")

    # --- network reachability ---
    if check_network:
        try:
            req = urllib.request.Request("https://api.abuseipdb.com/api/v2/", method="HEAD")
            urllib.request.urlopen(req, timeout=5)
            ok("api.abuseipdb.com is reachable")
        except urllib.error.HTTPError:
            # Any HTTP response at all — even an error one — means DNS,
            # routing, and TLS all worked; that's what's being checked.
            ok("api.abuseipdb.com is reachable")
        except Exception as e:
            warn(f"api.abuseipdb.com is not reachable: {e}")
    else:
        skip("Network reachability check skipped (--no-network)")

    # --- live self-test against the actually-running proxy ---
    # Everything above checks that *this* process's config/environment
    # looks right. It says nothing about whether the deployed, currently
    # running instance (started by systemd, possibly minutes or months
    # ago) is actually working — a stale process from before a config
    # change, a silently-dead listener, etc. wouldn't show up above at
    # all. This sends one synthetic alert through the proxy's real HTTP
    # endpoint on localhost and confirms it comes back with a 200.
    if check_network:
        live_result = run_live_self_test()
        if live_result["ok"]:
            ok(f"Live self-test: {live_result['detail']}")
        else:
            warn(f"Live self-test: {live_result['detail']}")
    else:
        skip("Live self-test skipped (--no-network)")

    return results


def run_live_self_test():
    """
    Sends one synthetic, guaranteed-harmless alert (192.0.2.1, an RFC 5737
    documentation-only IP that is always in the default ignore list — see
    IGNORE_NETWORKS — so this can never actually reach the real AbuseIPDB
    API, regardless of ABUSEIPDB_DRY_RUN) through the proxy's real HTTP
    endpoint on localhost, exercising the full path a live CrowdSec alert
    would take: TCP connect, the source-IP/shared-secret auth checks,
    JSON parsing, and IP filtering. A response confirms the *currently
    running* instance is actually listening and processing correctly —
    something --check-config's static checks can't tell you, since they
    only validate this process's own environment, not whether a
    long-running deployed instance is still healthy.

    Returns {"ok": bool, "detail": str}. Never raises.
    """
    host = "127.0.0.1" if LISTEN_ADDRESS in ("0.0.0.0", "::") else LISTEN_ADDRESS
    url = f"http://{host}:{LISTEN_PORT}/"
    headers = {"Content-Type": "application/json"}
    if SHARED_SECRET:
        headers["X-Proxy-Secret"] = SHARED_SECRET
    payload = json.dumps({
        "ip": "192.0.2.1",
        "categories": "15",
        "comment": "abuseipdb-proxy self-test (--doctor) — always filtered, never reported",
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        return {
            "ok": False,
            "detail": f"proxy at {url} responded with HTTP {e.code} — check "
                      f"ABUSEIPDB_SHARED_SECRET/ABUSEIPDB_ALLOWED_SOURCE_IPS if either is set",
        }
    except Exception as e:
        return {
            "ok": False,
            "detail": f"could not reach the proxy at {url}: {e}. Is the service actually running? "
                      f"(This checks the currently listening process, not this CLI invocation.)",
        }

    if status != 200:
        return {"ok": False, "detail": f"unexpected HTTP {status} from {url}"}
    return {"ok": True, "detail": f"{url} accepted and processed a synthetic test alert correctly"}


def format_doctor_output(results):
    symbols = {"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]", "skip": "[SKIP]"}
    lines = [f"{symbols[level]} {msg}" for level, msg in results]
    fail_count = sum(1 for level, _ in results if level == "fail")
    warn_count = sum(1 for level, _ in results if level == "warn")
    lines.append("")
    if fail_count:
        lines.append(f"{fail_count} problem(s), {warn_count} warning(s) — fix the [FAIL] items above.")
    elif warn_count:
        lines.append(f"No problems, {warn_count} warning(s) to review.")
    else:
        lines.append("All checks passed.")
    return "\n".join(lines)


BACKUP_RETENTION = int(os.getenv("ABUSEIPDB_BACKUP_RETENTION", "14"))


def run_migrate_to_sqlite(target_path=None):
    """
    One-shot migration for ABUSEIPDB_CACHE_BACKEND=json users (deprecated,
    removed entirely in 3.0.0): reads the currently-configured JSON cache
    and writes it into a SQLite database, without touching the live
    ABUSEIPDB_CACHE_BACKEND setting — that's a config change the person
    makes themselves afterward, once they've confirmed the migration
    looks right. Safe to re-run: it only ever reads the JSON file, never
    modifies or deletes it.
    """
    if CACHE_BACKEND != "json":
        return {
            "error": f"ABUSEIPDB_CACHE_BACKEND is already {CACHE_BACKEND!r} — nothing to migrate. "
                     f"This only migrates *from* the json backend."
        }

    if not os.path.exists(CACHE_FILE):
        return {"error": f"No JSON cache found at {CACHE_FILE} — nothing to migrate."}

    try:
        with open(CACHE_FILE, "r") as f:
            data = json.load(f)
    except Exception as e:
        return {"error": f"Could not read {CACHE_FILE}: {e}"}

    if "reports" in data or "pending" in data or "retry_queue" in data:
        data.setdefault("reports", {})
        data.setdefault("pending", {})
        data.setdefault("retry_queue", {})
    else:
        data = {"reports": data, "pending": {}, "retry_queue": {}}  # v1.0.0 flat format

    if not target_path:
        base, _ = os.path.splitext(CACHE_FILE)
        target_path = base + ".db"

    if os.path.exists(target_path):
        return {
            "error": f"{target_path} already exists — refusing to overwrite it. "
                     f"Pass an explicit --migrate-to-sqlite=PATH to choose a different target, "
                     f"or remove the existing file first if you're sure it's safe to replace."
        }

    try:
        _save_cache_sqlite(data, path=target_path)
    except Exception as e:
        return {"error": f"Migration failed: {e}"}

    entry_count = sum(len(section) for section in data.values())
    return {
        "source": CACHE_FILE,
        "target": target_path,
        "entries": entry_count,
    }


def run_backup(backup_dir=None):
    """
    Writes a timestamped, portable JSON snapshot of the cache (the same
    format --export produces) into backup_dir, then prunes older backups
    beyond ABUSEIPDB_BACKUP_RETENTION (default 14) — keeps the most
    recent N regardless of age, since a fixed time window doesn't map
    cleanly across wildly different backup intervals (someone running
    this hourly vs. weekly).
    """
    if backup_dir is None:
        backup_dir = os.path.join(os.path.dirname(CACHE_FILE) or ".", "backups")
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = os.path.join(backup_dir, f"cache-{timestamp}.json")
    with open(backup_path, "w") as f:
        f.write(export_cache_json())

    existing = sorted(
        f for f in os.listdir(backup_dir)
        if f.startswith("cache-") and f.endswith(".json")
    )
    pruned = []
    while len(existing) > BACKUP_RETENTION:
        oldest = existing.pop(0)
        try:
            os.remove(os.path.join(backup_dir, oldest))
            pruned.append(oldest)
        except OSError:
            pass

    log(f"Backed up cache to {backup_path}.", path=backup_path)
    if pruned:
        log(f"Pruned {len(pruned)} old backup(s) beyond the {BACKUP_RETENTION}-backup retention.",
            pruned_count=len(pruned))

    return {"backup_path": backup_path, "pruned": pruned, "retention": BACKUP_RETENTION}


def fetch_crowdsec_active_decisions():
    """Queries CrowdSec's local API for currently active "ban" decisions,
    the same endpoint bouncers poll. Returns a list of (ip, scenario)
    tuples for scope=Ip decisions only (range/country-scoped decisions
    aren't single-IP reportable). `scenario` is "" for decisions with no
    scenario name (e.g. added manually via `cscli decisions add`).
    Raises on any network/auth/parse failure; callers decide how to
    handle that."""
    url = f"{CROWDSEC_LAPI_URL}/v1/decisions?type=ban"
    req = urllib.request.Request(url, headers={"X-Api-Key": CROWDSEC_BOUNCER_KEY, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data:  # CrowdSec returns `null` (not `[]`) when there are no active decisions
        return []
    return [
        (d["value"], d.get("scenario") or "") for d in data
        if d.get("value") and d.get("scope", "Ip").lower() == "ip"
    ]


def run_reconcile(as_json=False):
    """
    Catch-up job: reports any IP CrowdSec currently has actively banned
    but that never made it into this proxy's own report cache — the
    signal that a live alert was missed (proxy downtime, a dropped
    notification, etc.), not a substitute for the normal live path. Goes
    through the exact same process_alert() as a live alert, so existing
    dedup/escalation/quota-reservation/whitelist logic all still applies;
    an IP already tracked in the cache is left alone.

    Categories/severity are derived from the decision's own scenario name
    via categories_for_scenario()/get_severity() — the same categorization
    a live alert for that scenario would have gotten. Only decisions with
    no scenario name at all (manually-added bans) fall back to the fixed
    ABUSEIPDB_RECONCILE_SEVERITY/_CATEGORIES.
    """
    if not CROWDSEC_BOUNCER_KEY:
        return {
            "error": "ABUSEIPDB_CROWDSEC_BOUNCER_KEY is not set. Create one with "
                     "'cscli bouncers add <name>' on the CrowdSec host and set its API key here."
        }

    try:
        active_decisions = fetch_crowdsec_active_decisions()
    except Exception as e:
        return {"error": f"Could not reach CrowdSec LAPI at {CROWDSEC_LAPI_URL}: {e}"}

    with lock:
        cache = load_cache()
        known_ips = set(cache.get("reports", {}).keys())

    checked = len(active_decisions)
    already_known = 0
    skipped_ignored = 0
    reconciled = []
    threads = []

    for ip, scenario in active_decisions:
        if ip in known_ips:
            already_known += 1
            continue
        if is_ignored_ip(ip):
            skipped_ignored += 1
            continue
        if is_whitelisted(ip):
            skipped_ignored += 1
            continue

        categories = categories_for_scenario(scenario)
        if categories is not None:
            severity = get_severity(categories)
            comment = (
                f"CrowdSec blocked IP for {scenario} (reconciled — proxy had no record "
                f"of reporting this)"
            )
        else:
            categories = RECONCILE_CATEGORIES
            severity = RECONCILE_SEVERITY
            comment = (
                "Reconciled from an active CrowdSec decision with no scenario name "
                "(likely added manually) that the proxy had no record of reporting."
            )

        t = process_alert(ip, categories, comment, severity)
        if t:
            threads.append(t)
        reconciled.append(ip)

    # Unlike the live HTTP path (which stays running for hours after
    # firing these off), this is a one-shot CLI run — without waiting
    # here, the process could exit and kill these daemon threads mid-request,
    # even though the cache already optimistically marked them as reported.
    for t in threads:
        t.join(timeout=15)

    result = {
        "checked": checked,
        "already_known": already_known,
        "skipped_ignored_or_whitelisted": skipped_ignored,
        "reconciled": reconciled,
        "reconciled_count": len(reconciled),
    }
    if reconciled:
        # Worth surfacing through the configured alerting backends, not
        # just the log — this only runs periodically (typically an hourly
        # timer), and finding something here means the live path missed
        # a report, which is itself worth knowing about even once fixed.
        # Capped so a big catch-up run (proxy down for a day, say)
        # doesn't produce a message too large for some backends (Telegram,
        # ntfy, etc. all have their own limits).
        shown = reconciled[:20]
        ip_list = ", ".join(shown)
        if len(reconciled) > len(shown):
            ip_list += f", and {len(reconciled) - len(shown)} more"
        notify(
            f"Reconciliation found {len(reconciled)} of {checked} active CrowdSec "
            f"decision(s) missing from the report cache and reported them: {ip_list}",
            priority="normal",
        )
    if not as_json:
        if reconciled:
            log(f"Reconciliation: {len(reconciled)} of {checked} active CrowdSec decision(s) "
                f"were missing from the report cache and have been queued for reporting.",
                reconciled_count=len(reconciled), checked=checked)
        else:
            log(f"Reconciliation: all {checked} active CrowdSec decision(s) were already "
                f"accounted for.", checked=checked)
    return result


def parse_args():
    parser = argparse.ArgumentParser(description="CrowdSec Smart AbuseIPDB Proxy")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would be reported instead of calling the AbuseIPDB API "
             "(same effect as ABUSEIPDB_DRY_RUN=true).",
    )
    parser.add_argument(
        "--test-notify",
        action="store_true",
        help="Send a test message to all configured notification backends and exit.",
    )
    parser.add_argument(
        "--notify",
        metavar="MESSAGE",
        help="Send MESSAGE to all configured notification backends and exit. "
             "Used internally by update.sh --check-only; also handy for scripting.",
    )
    parser.add_argument(
        "--notify-priority",
        choices=["low", "normal", "high"],
        default="normal",
        help="Priority for --notify (default: normal).",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the version and exit.",
    )
    parser.add_argument(
        "--export",
        metavar="PATH", nargs="?", const="-", default=None,
        help="Export the current cache (reports/pending/retry_queue) as portable JSON to PATH, "
             "or to stdout if PATH is omitted or '-'. Works the same regardless of which cache "
             "backend (json/sqlite) is currently active.",
    )
    parser.add_argument(
        "--import", dest="import_cache",
        metavar="PATH",
        help="Replace the current cache with a JSON snapshot from PATH (or '-' for stdin), "
             "as produced by --export. Prompts for confirmation unless -y/--yes is also given.",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip the confirmation prompt for --import.",
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Prune stale reports and VACUUM the SQLite cache to reclaim disk space, then exit. "
             "No-op on the JSON backend. Safe to run anytime; suitable for a periodic timer.",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the current configuration (env vars) — API key, cache path, alerting "
             "backends, timing settings — and exit. Exit code is 1 if anything failed, 0 "
             "otherwise (warnings alone don't fail it). No network access, no changes made.",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Everything --check-config covers, plus systemd service status, file permissions, "
             "whether CrowdSec's profiles.yaml actually wires this notification up, cache "
             "readability, whether api.abuseipdb.com is reachable, and (unless --no-network) a "
             "live self-test — a synthetic, always-filtered test alert sent through the actually "
             "running proxy's real HTTP endpoint, confirming the deployed instance is truly "
             "listening and working end-to-end, not just that this CLI invocation's config looks "
             "right. Bare-metal-specific checks skip themselves cleanly when they don't apply "
             "(e.g. in Docker). Exit code is 1 if anything failed, 0 otherwise.",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="With --doctor, skip the api.abuseipdb.com reachability check and the live self-test.",
    )
    parser.add_argument(
        "--backup",
        metavar="DIR", nargs="?", const=None, default="__unset__",
        help="Write a timestamped snapshot of the cache into DIR (default: a 'backups' "
             "subdirectory next to the cache file itself), then prune old backups beyond "
             "ABUSEIPDB_BACKUP_RETENTION (default 14). Suitable for a periodic timer.",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show a snapshot of what's currently in the cache (recent reports, pending "
             "escalations, queued retries, AbuseIPDB quota) and exit. Reads the cache directly, "
             "so this works against a running service's cache without needing to hit /health or "
             "/metrics. For live since-start counters (reports sent/suppressed/failed), see "
             "/metrics on the running instance instead.",
    )
    parser.add_argument(
        "--stats-limit",
        type=int, default=10, metavar="N",
        help="How many recent reports to list with --stats (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="With --stats, print machine-readable JSON instead of the human-readable summary.",
    )
    parser.add_argument(
        "--reconcile",
        action="store_true",
        help="Compare CrowdSec's currently active decisions (via its local API) against this "
             "proxy's report cache, and report any that are missing — catches reports lost to "
             "proxy downtime. Requires ABUSEIPDB_CROWDSEC_BOUNCER_KEY. Suitable for a periodic "
             "timer, e.g. hourly.",
    )
    parser.add_argument(
        "--migrate-to-sqlite",
        metavar="PATH", nargs="?", const=None, default="__unset__",
        help="One-time migration for ABUSEIPDB_CACHE_BACKEND=json setups (deprecated, removed "
             "in 3.0.0): writes the current JSON cache into a new SQLite database at PATH "
             "(default: same name as the JSON file with a .db extension) without deleting the "
             "JSON file or changing your configuration. Refuses to overwrite an existing target "
             "file. Update ABUSEIPDB_CACHE_BACKEND=sqlite (and ABUSEIPDB_CACHE_FILE if needed) "
             "afterward.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.version:
        print(f"CrowdSec Smart AbuseIPDB Proxy v{VERSION}")
        sys.exit(0)

    if args.vacuum:
        vacuum_cache()
        sys.exit(0)

    if args.stats:
        stats = build_stats(limit=args.stats_limit)
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(format_stats_text(stats))
        sys.exit(0)

    if args.export is not None:
        output = export_cache_json()
        if args.export == "-":
            print(output)
        else:
            with open(args.export, "w") as f:
                f.write(output)
            log(f"Exported cache to {args.export}.", path=args.export)
        sys.exit(0)

    if args.import_cache is not None:
        try:
            if args.import_cache == "-":
                raw = sys.stdin.read()
            else:
                with open(args.import_cache, "r") as f:
                    raw = f.read()
            new_cache = import_cache_json(raw)
        except (OSError, ValueError) as e:
            log(f"Import failed: {e}", level="error")
            sys.exit(1)

        entry_count = sum(len(section) for section in new_cache.values())
        if not args.yes:
            answer = input(
                f"This will REPLACE the current cache ({CACHE_BACKEND} backend, {CACHE_FILE}) "
                f"with {entry_count} entries from {args.import_cache}. Continue? [y/N] "
            )
            if answer.strip().lower() not in ("y", "yes"):
                print("Aborted.")
                sys.exit(1)

        with lock:
            save_cache(new_cache)
        log(f"Imported {entry_count} entries into the cache.", entries=entry_count)
        sys.exit(0)

    if args.dry_run:
        DRY_RUN = True

    if args.check_config:
        results = check_config()
        if args.json:
            print(json.dumps([{"level": level, "message": msg} for level, msg in results], indent=2))
        else:
            print(format_config_check(results))
        sys.exit(1 if any(level == "fail" for level, _ in results) else 0)

    if args.doctor:
        results = run_doctor(check_network=not args.no_network)
        if args.json:
            print(json.dumps([{"level": level, "message": msg} for level, msg in results], indent=2))
        else:
            print(format_doctor_output(results))
        sys.exit(1 if any(level == "fail" for level, _ in results) else 0)

    if args.backup != "__unset__":
        result = run_backup(backup_dir=args.backup)
        if args.json:
            print(json.dumps(result, indent=2))
        sys.exit(0)

    if args.migrate_to_sqlite != "__unset__":
        result = run_migrate_to_sqlite(target_path=args.migrate_to_sqlite)
        if args.json:
            print(json.dumps(result, indent=2))
        elif "error" in result:
            print(f"Migration failed: {result['error']}")
        else:
            print(
                f"Migrated {result['entries']} entries from {result['source']} "
                f"to {result['target']}.\n\n"
                f"Next: set ABUSEIPDB_CACHE_BACKEND=sqlite and "
                f"ABUSEIPDB_CACHE_FILE={result['target']} in your env file, then restart. "
                f"The JSON file was not modified or deleted."
            )
        sys.exit(1 if "error" in result else 0)

    if args.reconcile:
        if args.dry_run:
            DRY_RUN = True
        if not API_KEY and not DRY_RUN:
            print("Reconciliation failed: ABUSEIPDB_API_KEY is not set "
                  "(use --dry-run to preview without it).")
            sys.exit(1)
        result = run_reconcile(as_json=args.json)
        if args.json:
            print(json.dumps(result, indent=2))
        elif "error" in result:
            print(f"Reconciliation failed: {result['error']}")
        else:
            print(f"Checked {result['checked']} active CrowdSec decision(s): "
                  f"{result['already_known']} already known, "
                  f"{result['skipped_ignored_or_whitelisted']} skipped (ignored/whitelisted), "
                  f"{result['reconciled_count']} reconciled.")
            if result["reconciled"]:
                print("Reconciled: " + ", ".join(result["reconciled"]))
        sys.exit(1 if "error" in result else 0)

    def _send_and_exit(message, priority):
        if not (GOTIFY_URL or NTFY_URL or WEBHOOK_URL or SLACK_WEBHOOK_URL
                or DISCORD_WEBHOOK_URL or (MATRIX_HOMESERVER_URL and MATRIX_ACCESS_TOKEN and MATRIX_ROOM_ID)
                or (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) or (HOMEASSISTANT_URL and HOMEASSISTANT_TOKEN)):
            log(
                "No notification backend configured "
                "(ABUSEIPDB_GOTIFY_URL / ABUSEIPDB_NTFY_URL / ABUSEIPDB_WEBHOOK_URL / "
                "ABUSEIPDB_SLACK_WEBHOOK_URL / ABUSEIPDB_DISCORD_WEBHOOK_URL / "
                "ABUSEIPDB_MATRIX_* / ABUSEIPDB_TELEGRAM_* / ABUSEIPDB_HOMEASSISTANT_*). Nothing to send.",
                level="error",
            )
            sys.exit(1)
        notify(message, priority=priority)
        time.sleep(3)  # let the background threads finish before the process exits
        sys.exit(0)

    if args.test_notify:
        log(f"Sending test notification as '{NOTIFY_NAME}'...")
        _send_and_exit(
            f"This is a test notification from {NOTIFY_NAME}. If you can read this, alerting works.",
            priority="normal",
        )

    if args.notify is not None:
        _send_and_exit(args.notify, priority=args.notify_priority)

    if not API_KEY and not DRY_RUN:
        log(
            "ERROR: environment variable ABUSEIPDB_API_KEY is not set. "
            "Aborting. (Use --dry-run / ABUSEIPDB_DRY_RUN=true to run without a key.)",
            level="error",
        )
        sys.exit(1)

    print_startup_banner()

    if DRY_RUN:
        log("Dry-run mode enabled: no reports will be sent to AbuseIPDB.")

    if CACHE_BACKEND == "json":
        log(
            "ABUSEIPDB_CACHE_BACKEND=json is deprecated and will be removed in 3.0.0. "
            "Run 'abuseipdb_proxy.py --migrate-to-sqlite' to switch over, then set "
            "ABUSEIPDB_CACHE_BACKEND=sqlite.",
            level="warning",
        )

    ensure_cache_dir()
    resume_state_from_cache()
    if SUMMARY_INTERVAL > 0:
        threading.Thread(target=_summary_loop, daemon=True).start()
    if NOTIFY_ON_START:
        mode = "dry-run" if DRY_RUN else "live"
        notify(f"Started ({mode} mode).", priority="low")
    # ThreadingHTTPServer: one thread per connection instead of handling
    # requests one at a time. Every module-level piece of state a request
    # can touch (the report cache, pending/retry timers, quota tracking,
    # the whitelist cache, the active-API-key switch) is guarded by its
    # own lock — see the comment on `lock` above — specifically so this
    # is safe. daemon_threads=True so in-flight request threads don't
    # block a shutdown. request_queue_size raised from the default of 5:
    # CrowdSec can fire several alerts in quick succession (e.g. a
    # coordinated attack tripping multiple scenarios at once), and the
    # default backlog is small enough that a real burst could get
    # connections refused/reset before a thread is even spun up to
    # accept them.
    http.server.ThreadingHTTPServer.daemon_threads = True
    http.server.ThreadingHTTPServer.request_queue_size = 128
    server = http.server.ThreadingHTTPServer((LISTEN_ADDRESS, LISTEN_PORT), AbuseIPDBHandler)
    log(f"Listening on {LISTEN_ADDRESS}:{LISTEN_PORT}.", address=LISTEN_ADDRESS, port=LISTEN_PORT)
    server.serve_forever()
