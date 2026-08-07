# CrowdSec Smart AbuseIPDB Proxy

[![CI](https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy)](https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy/releases/latest)
![Python 3](https://img.shields.io/badge/python-3-blue.svg)
![Shell](https://img.shields.io/badge/shell-bash-89e051.svg)

🇬🇧 English | 🇩🇪 [Deutsch](README.de.md)

A lightweight local proxy that forwards CrowdSec alerts to AbuseIPDB intelligently — with deduplication, severity escalation, and rate-limit protection, so you don't get throttled by AbuseIPDB for spamming reports.

<p align="center">
  <img src="assets/demo.gif" alt="CrowdSec Smart Proxy Doctor Check" width="450">
</p>

<details>
<summary><strong>Table of contents</strong></summary>

- [The problem](#the-problem)
- [The solution](#the-solution)
  - [Severity mapping](#severity-mapping)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Updating](#updating)
  - [Re-running / changing the key](#re-running--changing-the-key)
- [Uninstall](#uninstall)
- [Docker](#docker)
  - [Updating](#updating-1)
- [Configuration](#configuration-optional-via-environment-variables)
- [Logs](#logs)
- [Log volume (honeypots / high-traffic setups)](#log-volume-honeypots--high-traffic-setups)
- [CLI reference](#cli-reference)
- [Endpoints](#endpoints)
- [Alerting](#alerting-optional)
- [CrowdSec decision reconciliation](#crowdsec-decision-reconciliation-optional)
- [Version history](#version-history)
- [Files in this repo](#files-in-this-repo)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)

</details>

## The problem

CrowdSec can report alerts directly to AbuseIPDB via its HTTP notification plugin. The issue: if the same IP triggers multiple alerts in quick succession (e.g. an SSH brute-force attempt followed shortly after by a web exploit attempt), CrowdSec fires a separate report for every single alert. AbuseIPDB's API has fairly tight limits, and repeated reports for the same IP in a short time window don't add real value — they just burn through your quota.

## The solution

This proxy sits between CrowdSec and AbuseIPDB and makes a simple decision for every IP:

- **New IP?** → Report immediately.
- **IP was already reported in the last 24h?**
  - Alert with **equal or lower severity** → ignored (no added value).
  - Alert with **higher severity** (e.g. escalating from a port scan to an exploit attempt):
    - If **≥ 15 minutes** have passed since the last report → report immediately.
    - Otherwise → the report is **delayed** and sent once the 15-minute window is up (no spamming, but the escalation is never lost).

This means AbuseIPDB gets at most one report per IP per 15-minute window, while a genuine escalation is never dropped.

### Severity mapping

Based on [AbuseIPDB's full category list](https://www.abuseipdb.com/categories), mapped to an internal severity used for deduplication and escalation:

| Severity | Categories |
|---|---|
| 1 (low) | Open Proxy, Web Spam, Email Spam, Blog Spam, VPN IP, Port Scan, Bad Web Bot |
| 2 (medium) | Fraud Orders, FTP Brute-Force, Ping of Death, Fraud VoIP, Spoofing, Brute-Force, Web App Attack, SSH, IoT Targeted |
| 3 (high) | DNS Compromise, DNS Poisoning, DDoS Attack, Phishing, Hacking, SQL Injection, Exploited Host |

The CrowdSec notification template (`abuseipdb.yaml`) maps common scenario name patterns (`ssh`, `telnet`, `sqli`, `cve`, generic `-bf` suffixes, etc.) to the right categories automatically — see the file for the full list. Matching is case-insensitive.

## Architecture

```
CrowdSec Alert → HTTP notification plugin → local proxy (port 9999) → AbuseIPDB API
```

The proxy listens exclusively on `127.0.0.1`, so it's not reachable from outside the host.

<p align="center">
  <img src="assets/architecture.png" alt="CrowdSec Smart AbuseIPDB Proxy Architektur" width="300">
</p>

## Requirements

- CrowdSec with the [HTTP notification plugin](https://docs.crowdsec.net/docs/notification_plugins/http) enabled
- Python 3 (no external dependencies, standard library only)
- An [AbuseIPDB API key](https://www.abuseipdb.com/account/api)
- root privileges on the target host

## Installation

```bash
git clone https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy.git
cd CrowdSec-Smart-AbuseIPDB-Proxy
sudo ./install.sh
```

The installer will interactively ask for your AbuseIPDB API key and takes care of:

1. Copying the proxy script to `/usr/local/bin/abuseipdb_proxy.py`
2. Creating a persistent cache directory at `/var/lib/abuseipdb-proxy`
3. Storing the API key in `/etc/abuseipdb-proxy/abuseipdb-proxy.env` (chmod 600, root-readable only)
4. Installing the `abuseipdb-proxy.service` systemd unit
5. Installing the CrowdSec notification to `/etc/crowdsec/notifications/abuseipdb.yaml`
6. Enabling and starting the service, reloading CrowdSec

**One manual step is left on purpose:** the notification needs to be referenced in `/etc/crowdsec/profiles.yaml`, e.g.:

```yaml
notifications:
  - abuseipdb_default
```

The script checks whether that entry already exists but won't add it automatically, since `profiles.yaml` layouts vary a lot between setups.

### Updating

```bash
cd CrowdSec-Smart-AbuseIPDB-Proxy
./update.sh
```

**Upgrading from v1.x?** v2.0.0 switches the default cache backend from a single JSON file to SQLite (see `ABUSEIPDB_CACHE_BACKEND` below for why). This runs itself automatically and won't lose any history: the first time the proxy starts after the upgrade, it finds your existing `cache.json`, imports it into the new `cache.db`, and renames the old file to `cache.json.migrated` — kept as a backup, never deleted. Nothing to do on your end; check the log for the "Migration complete" line if you want to confirm it happened. Prefer to stick with the JSON file? Set `ABUSEIPDB_CACHE_BACKEND=json` and nothing changes for you.

Checks for new commits on `origin/main`, refuses to run if you have uncommitted local changes, shows what changed (including the relevant `CHANGELOG.md` section if the version bumped), then pulls and re-runs `install.sh` for you. Safe to run anytime — does nothing if you're already up to date. Add `-y` to skip the confirmation prompt (e.g. for a cron job).

**Just want to be notified, not auto-updated?** Use `./update.sh --check-only` — it only checks and, if something's new, sends a notification through whichever alerting backend you already configured (see below), without touching anything. `install.sh` offers to set this up as a daily systemd timer (`abuseipdb-proxy-update-check.timer`) so you get a heads-up without ever auto-applying changes to a security-relevant tool unattended.

**Feeding this into your own tooling instead?** Add `--json` (only valid together with `--check-only`) for a single-line machine-readable result instead of the human-readable output:
```bash
./update.sh --check-only --json
# {"update_available": true, "current_version": "1.5.0", "new_version": "1.6.1", "commit_count": 3, "notified": true}
```

You can always check what's actually running with:
```bash
abuseipdb_proxy.py --version
```

### Re-running / changing the key

`install.sh` is safe to re-run directly too. If a key already exists at `/etc/abuseipdb-proxy/abuseipdb-proxy.env`, the script asks whether to keep it or overwrite it.

## Uninstall

```bash
sudo ./uninstall.sh
```

Removes everything `install.sh` created (service, binary, config, cache, CrowdSec notification), with an option to keep the API key and cache around in case you reinstall later. Leaves `profiles.yaml` untouched — remove the `abuseipdb_default` entry from it by hand afterward.

## Docker

An alternative to `install.sh` for anyone already running CrowdSec (or willing to) in containers. Everything Docker-related lives in `Docker/`, kept separate from the bare-metal install at the repo root. Pre-built multi-arch images (`linux/amd64`, `linux/arm64` — Raspberry Pi included) are published to GHCR on every release; no local build needed. The image has zero third-party Python dependencies — the proxy is stdlib-only — so it's a small, standard `python:3.13-alpine` build with nothing extra installed; CI builds it and reports the actual size on every push. Resource footprint at runtime is minimal too: a single-threaded process handling occasional alerts, well under 64MB RAM in practice (see the commented `mem_limit`/`cpus` in `Docker/docker-compose.yml` if you want a hard ceiling anyway).

```bash
cd Docker
cp docker-compose.env.example docker-compose.env
# edit docker-compose.env: at minimum set ABUSEIPDB_API_KEY
docker compose up -d
```

That's it — `Docker/docker-compose.yml` pulls the published image (`ghcr.io/pumbalp/crowdsec-smart-abuseipdb-proxy:latest`), built and pushed automatically on every release; there's nothing to build locally. Run every `docker compose` command from inside `Docker/` (or add `-f Docker/docker-compose.yml` from the repo root instead) — it resolves `docker-compose.env` relative to its own location. Contributing a change to the Dockerfile itself? See `CONTRIBUTING.md` for how to build and test it locally.

**Verifying the image**: every published image is signed (keyless, via [cosign](https://github.com/sigstore/cosign) and Sigstore) and ships an SPDX SBOM, both attached in CI. To verify a pull:
```bash
cosign verify ghcr.io/pumbalp/crowdsec-smart-abuseipdb-proxy:latest \
  --certificate-identity-regexp "^https://github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A few things that differ from the bare-metal install:

- **Networking**: the container listens on `0.0.0.0:9999` inside Docker's own network isolation (not published to the host by default — see the commented-out `ports:` block in `docker-compose.yml` if you actually need that). CrowdSec needs to reach this container by its Docker service name, not `127.0.0.1`: change `abuseipdb.yaml`'s `url` to `http://abuseipdb-proxy:9999/`, and make sure CrowdSec's own container is on the same Docker network — see the `networks:` comments in `docker-compose.yml` for how to join an existing CrowdSec compose project's network.
- **Cache**: persisted in a named Docker volume (`abuseipdb-cache`), not `/var/lib/abuseipdb-proxy` on the host. `docker compose down` alone won't touch it; `docker compose down -v` will.
- **The CrowdSec-side setup** (`abuseipdb.yaml`, `profiles.yaml`) is unchanged either way — this only replaces how the proxy itself runs, not how CrowdSec talks to it (beyond the URL above).
- **CLI flags** (`--stats`, `--vacuum`, `--export`, `--test-notify`, `--reconcile`, ...) still work: `docker compose exec abuseipdb-proxy python3 abuseipdb_proxy.py --stats`, etc.
- **`--reconcile`**: the systemd timer this repo ships (`abuseipdb-proxy-reconcile.timer`) is bare-metal only. For Docker, schedule it yourself with a host cron job instead, e.g. hourly: `0 * * * * cd /path/to/Docker && docker compose exec -T abuseipdb-proxy python3 abuseipdb_proxy.py --reconcile`. Also set `ABUSEIPDB_CROWDSEC_LAPI_URL` to wherever CrowdSec's container is actually reachable from this one — `http://127.0.0.1:8080` (the default) is almost never right inside Docker; typically `http://crowdsec:8080` if it's on the same Docker network (see "Networking" above for joining CrowdSec's network).
- **Secrets**: any `{VARIABLE}_FILE` override (see "Configuration" above) works in Docker too — `docker-compose.yml` has a commented example volume mount for it.

### Updating

Manually, from inside `Docker/`: `docker compose pull && docker compose up -d`. (`update.sh`/`--check-only` assume a bare-metal git checkout and don't apply to the Docker setup.)

**Set and forget instead?** `Docker/docker-compose.yml` includes a commented-out [Watchtower](https://containrrr.dev/watchtower/) service specifically scoped to this container (via a label, so it won't touch anything else Docker-based on the same host). Uncomment it and you're done — checks daily by default. It defaults to `WATCHTOWER_MONITOR_ONLY=true`: sends you a notification when an update is available but doesn't apply it automatically, the same "tell me, don't just do it" philosophy as `update.sh --check-only` for the bare-metal install. Point `WATCHTOWER_NOTIFICATION_URL` at the same alerting backend you already configured for the proxy (Watchtower uses [shoutrrr](https://containrrr.dev/shoutrrr/) URLs — Slack/Discord/Gotify/ntfy and more are supported, just in a different URL format than this proxy's own `ABUSEIPDB_*` variables). Want it to actually auto-apply instead? Delete the `WATCHTOWER_MONITOR_ONLY` line.

Image tags: `latest` (newest release), `X.Y.Z`/`X.Y`/`X` (pin to a specific version or track a major/minor line), or `sha-<commit>` (exact build provenance).

## Configuration (optional, via environment variables)

All set in `/etc/abuseipdb-proxy/abuseipdb-proxy.env`:

Any secret-like variable below (API key, tokens, webhook URLs, the shared secret) also accepts a `{VARIABLE}_FILE` override — set it to a file path instead of putting the value itself in the env file, for Docker/Podman secrets or a mount from a secrets manager. If both are set, `_FILE` wins. See `abuseipdb-proxy.env.example` / `Docker/docker-compose.env.example`.

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_API_KEY` | *(required)* | Your AbuseIPDB API key |
| `ABUSEIPDB_PROXY_PORT` | `9999` | Local port the proxy listens on |
| `ABUSEIPDB_LISTEN_ADDRESS` | `127.0.0.1` | Interface to bind to. Only change this from the loopback-only default in an isolated environment (e.g. inside Docker's own network — see "Docker" above); never expose it directly to an untrusted network. |
| `ABUSEIPDB_CACHE_FILE` | `/var/lib/abuseipdb-proxy/cache.db` (or `cache.json` when `ABUSEIPDB_CACHE_BACKEND=json`) | Path to the cache file |
| `ABUSEIPDB_CACHE_BACKEND` | `sqlite` | `sqlite` (a real database — `reports`/`pending`/`retry_queue` tables, WAL journal, scales well and is queryable with `sqlite3` directly) or `json` (single file, rewritten atomically — simpler to read by hand). An existing v1.x `cache.json` is imported into a fresh SQLite cache automatically on first run; see "Upgrading from v1.x" below. |
| `ABUSEIPDB_SQLITE_JOURNAL_MODE` | `WAL` | SQLite journal mode. Defaults are already SSD-friendly; rarely worth changing. Only used with the SQLite backend. |
| `ABUSEIPDB_SQLITE_SYNCHRONOUS` | `NORMAL` | SQLite sync mode. `FULL` trades some write-amplification for extra durability if you're on flaky storage (e.g. an SD card). Only used with the SQLite backend. |
| `ABUSEIPDB_REPORT_WINDOW` | `905` | Default time window in seconds between reports for the same IP |
| `ABUSEIPDB_REPORT_WINDOW_LOW` | same as `ABUSEIPDB_REPORT_WINDOW` | Window override for low-severity alerts |
| `ABUSEIPDB_REPORT_WINDOW_MEDIUM` | same as `ABUSEIPDB_REPORT_WINDOW` | Window override for medium-severity alerts |
| `ABUSEIPDB_REPORT_WINDOW_HIGH` | same as `ABUSEIPDB_REPORT_WINDOW` | Window override for high-severity alerts |
| `ABUSEIPDB_REPORT_WINDOW_CATEGORIES` | *(empty)* | Comma-separated `category=seconds` overrides for specific AbuseIPDB categories (e.g. `16=1800,20=3600`), finer-grained than the severity tiers above. Wins over the severity window when a reported category matches; the smallest matching window applies if more than one does. |
| `ABUSEIPDB_MAX_RETRIES` | `3` | How many times to retry a failed report before giving up |
| `ABUSEIPDB_RETRY_DELAY` | `900` | Seconds to wait before retrying a failed report (overridden by the API's `Retry-After` header when present, e.g. on a 429) |
| `ABUSEIPDB_DRY_RUN` | `false` | If `true`, log what would be reported instead of calling the AbuseIPDB API. Can also be set per-run with `--dry-run`. |
| `ABUSEIPDB_IGNORE_PRIVATE` | `true` | If `true`, silently skip RFC1918/loopback/link-local/CGNAT addresses (never worth reporting). Covers Tailscale's 100.64.0.0/10 range too. |
| `ABUSEIPDB_IGNORE_IPS` | *(empty)* | Extra comma-separated IPs/CIDRs to always skip, on top of the built-in private ranges |
| `ABUSEIPDB_ALLOWED_SOURCE_IPS` | *(empty)* | Comma-separated IPs/CIDRs allowed to POST to the proxy. Empty means no allowlist is enforced (matches current behavior). An extra layer on top of `ABUSEIPDB_LISTEN_ADDRESS`, mainly useful when the listener isn't loopback-only. |
| `ABUSEIPDB_SHARED_SECRET` | *(empty)* | If set, incoming POSTs must include a matching `X-Proxy-Secret` header (see the commented-out example in `abuseipdb.yaml`). Empty means no secret is required (matches current behavior). |
| `ABUSEIPDB_QUOTA_RESERVE_MEDIUM` | `0` | Reserve this many of the day's remaining AbuseIPDB reports for severity 2 and up, holding back severity-1 reports once remaining quota drops to or below it. `0` disables reservation. Only takes effect once the proxy has seen a remaining-quota count from AbuseIPDB. |
| `ABUSEIPDB_QUOTA_RESERVE_HIGH` | `0` | Same, but for severity 3 only — holds back severity 1 and 2 once remaining quota drops to or below it. Should normally be `<=` `ABUSEIPDB_QUOTA_RESERVE_MEDIUM`. `0` disables reservation. |
| `ABUSEIPDB_SKIP_WHITELISTED` | `false` | If `true`, skip reporting IPs that AbuseIPDB's own `/v2/check` marks as whitelisted (e.g. well-known crawlers/CDNs that opted in). Uses its own separate daily quota from `/v2/report`, and makes a synchronous network call on the request path for a cache miss — see `ABUSEIPDB_WHITELIST_CACHE_TTL`. |
| `ABUSEIPDB_WHITELIST_CACHE_TTL` | `86400` | Seconds an IP's whitelist-check result is cached in memory before being re-checked. Only relevant when `ABUSEIPDB_SKIP_WHITELISTED=true`. |
| `ABUSEIPDB_COMMENT_SCRUB_PATTERNS` | *(empty)* | Semicolon-separated regexes (not comma — regexes routinely contain commas, e.g. `{2,4}`). Any match in the comment text is replaced before the report is sent — AbuseIPDB comments are public. Invalid regexes are logged and skipped, not fatal. |
| `ABUSEIPDB_COMMENT_SCRUB_REPLACEMENT` | `[redacted]` | Replacement text for `ABUSEIPDB_COMMENT_SCRUB_PATTERNS` matches |
| `ABUSEIPDB_API_KEY_FALLBACK` | *(empty)* | A second AbuseIPDB API key to switch to once the primary's daily report quota is exhausted (detected via an HTTP 429 on `/v2/report`). Switches back to the primary automatically the first time a new UTC day is observed. |
| `ABUSEIPDB_CROWDSEC_LAPI_URL` | `http://127.0.0.1:8080` | CrowdSec's local API URL, used only by `--reconcile` |
| `ABUSEIPDB_CROWDSEC_BOUNCER_KEY` | *(empty)* | Bouncer API key for `--reconcile` (create one with `cscli bouncers add <name>` on the CrowdSec host). `--reconcile` does nothing without this set. |
| `ABUSEIPDB_RECONCILE_SEVERITY` | `2` | Fallback severity for `--reconcile`, used only when a decision has no scenario name at all (e.g. added manually via `cscli decisions add`) — otherwise severity is derived from the real scenario, same as a live alert |
| `ABUSEIPDB_RECONCILE_CATEGORIES` | `15` | Same fallback, for categories |
| `ABUSEIPDB_NOTIFY_NAME` | `CrowdSec Smart AbuseIPDB Proxy` | Display name used in alert notifications |
| `ABUSEIPDB_GOTIFY_URL` | *(empty)* | Base URL of your Gotify server, e.g. `https://gotify.example.com`. Activates the Gotify backend once both this and the token below are set. |
| `ABUSEIPDB_GOTIFY_TOKEN` | *(empty)* | Gotify application token |
| `ABUSEIPDB_NTFY_URL` | *(empty)* | Full ntfy topic URL, e.g. `https://ntfy.example.com/my-topic`. Activates the ntfy backend once set. |
| `ABUSEIPDB_NTFY_TOKEN` | *(empty)* | Optional ntfy access token (for protected topics) |
| `ABUSEIPDB_WEBHOOK_URL` | *(empty)* | Generic JSON webhook, for anything not natively supported — receives `{"name", "message", "priority"}` |
| `ABUSEIPDB_SLACK_WEBHOOK_URL` | *(empty)* | Slack Incoming Webhook URL. Activates the Slack backend once set. |
| `ABUSEIPDB_DISCORD_WEBHOOK_URL` | *(empty)* | Discord channel webhook URL. Activates the Discord backend once set. |
| `ABUSEIPDB_MATRIX_HOMESERVER_URL` | *(empty)* | Matrix homeserver URL, e.g. `https://matrix.org`. All three Matrix variables are required together. |
| `ABUSEIPDB_MATRIX_ACCESS_TOKEN` | *(empty)* | Access token for the Matrix account the proxy posts as |
| `ABUSEIPDB_MATRIX_ROOM_ID` | *(empty)* | Room ID to post into, e.g. `!roomid:matrix.org` — the account above must already be a member |
| `ABUSEIPDB_TELEGRAM_BOT_TOKEN` | *(empty)* | Telegram bot token from [@BotFather](https://t.me/BotFather). Activates the Telegram backend once set together with the chat ID. |
| `ABUSEIPDB_TELEGRAM_CHAT_ID` | *(empty)* | Telegram chat ID to send to |
| `ABUSEIPDB_HOMEASSISTANT_URL` | *(empty)* | Home Assistant base URL, e.g. `https://homeassistant.local:8123`. Both this and the token are required together. |
| `ABUSEIPDB_HOMEASSISTANT_TOKEN` | *(empty)* | Long-Lived Access Token from your HA user profile |
| `ABUSEIPDB_HOMEASSISTANT_NOTIFY_SERVICE` | `notify` | Which `notify.<service>` to call — `notify` is the generic one; use e.g. `mobile_app_myphone` to target a specific device |
| `ABUSEIPDB_BACKUP_RETENTION` | `14` | How many timestamped snapshots `--backup` keeps before pruning the oldest |
| `ABUSEIPDB_VERBOSE_LOGGING` | `false` | If `true`, log a line per successful report and per ignored private IP. Off by default — see "Log volume" below. |
| `ABUSEIPDB_LOG_FORMAT` | `text` | `text` (the traditional `[abuseipdb-proxy] message` line) or `json` (one JSON object per line — timestamp/level/message plus extra structured fields depending on the event — for Loki/ELK/Graylog etc.) |
| `ABUSEIPDB_QUOTA_WARN_THRESHOLD` | `50` | Send a one-time-per-day notification (via any configured alerting backend) when the AbuseIPDB daily report quota drops to or below this many remaining. Tracked from the API's own `X-RateLimit-Remaining` response header — also visible via `/health` and `/metrics`. |
| `ABUSEIPDB_SUMMARY_INTERVAL` | `300` | Seconds between periodic summary log lines (sent/suppressed/failed/ignored counts). `0` disables it. |
| `ABUSEIPDB_ENABLE_HEALTH` | `false` | Set to `true` to enable the `/health` endpoint |
| `ABUSEIPDB_ENABLE_METRICS` | `false` | Set to `true` to enable the `/metrics` endpoint |
| `ABUSEIPDB_NOTIFY_ON_START` | `false` | If `true`, send a low-priority notification via any configured alerting backend every time the proxy starts — useful to confirm an update actually restarted the service |

## Logs

```bash
journalctl -u abuseipdb-proxy.service -f
```

Failed reports and cache write errors are logged there (previously, API call errors were silently swallowed — that's now fixed).

Redirecting the proxy's own output to a plain file instead (rather than journald or Docker's log driver, both of which already rotate on their own)? `abuseipdb-proxy.logrotate` has a ready-to-use config — see the comment at its top for the one-line install.

## Log volume (honeypots / high-traffic setups)

By default, the proxy stays quiet under load: instead of a log line per report, it logs one periodic summary line (interval controlled by `ABUSEIPDB_SUMMARY_INTERVAL`, default 300s), and only when something actually happened in that window. Retries, give-ups, and notification failures still always log immediately — those are inherently rare, not volume-driven.

If you want per-event detail for troubleshooting on a low-traffic host, set `ABUSEIPDB_VERBOSE_LOGGING=true`.

Two additional safety nets, independent of the app's own logging:

- **`abuseipdb-proxy.service`** sets `LogRateLimitIntervalSec=30` / `LogRateLimitBurst=200`, capping the service at 200 journal lines per 30s no matter what — protects against a future logging bug or an unusually chatty CrowdSec scenario, without you having to think about it.
- **journald itself** has global limits worth knowing about on a honeypot host in general (not specific to this proxy): `SystemMaxUse=` / `RuntimeMaxUse=` in `/etc/systemd/journald.conf` cap total disk/RAM usage, and `Storage=persistent` vs `volatile` decides whether logs live on disk or only in a RAM-backed tmpfs. Worth checking those once if you're running a honeypot that generates a lot of CrowdSec activity in general.

## CLI reference

Beyond just running the proxy itself, `abuseipdb_proxy.py` (or `abuseipdb_proxy.py` on `$PATH` once installed) has a few standalone maintenance flags — all read/write the cache directly and exit, none of them start the HTTP server:

| Flag | What it does |
|---|---|
| `--version` | Print the version and exit. |
| `--dry-run` | Log what would be reported instead of calling the AbuseIPDB API (same as `ABUSEIPDB_DRY_RUN=true`). |
| `--stats [--json] [--stats-limit N]` | Snapshot of the cache: recent reports, pending escalations, queued retries, AbuseIPDB quota. `--json` for scripting; `--stats-limit` caps the recent-reports list (default 10). |
| `--export [PATH]` | Export the cache as portable JSON to PATH, or stdout if omitted. |
| `--import PATH [-y]` | Replace the cache with a JSON snapshot from PATH (or `-` for stdin). Prompts for confirmation unless `-y`/`--yes`. |
| `--vacuum` | Prune stale reports and reclaim disk space on the SQLite backend. No-op on JSON. |
| `--backup [DIR]` | Write a timestamped cache snapshot into DIR (default: `backups/` next to the cache file), then prune old backups beyond `ABUSEIPDB_BACKUP_RETENTION` (default 14). Suitable for a periodic timer. |
| `--check-config [--json]` | Validate the configuration (API key, cache path, alerting backends, timing) with no network access and no changes made. Exit code 1 if anything failed. |
| `--doctor [--no-network] [--json]` | Everything `--check-config` covers, plus systemd service status, file permissions, CrowdSec `profiles.yaml` wiring, cache readability, and (unless `--no-network`) whether api.abuseipdb.com is reachable. Bare-metal-specific checks skip cleanly outside that context (e.g. in Docker). |
| `--test-notify` | Send a test message to every configured alerting backend. |
| `--notify MESSAGE [--notify-priority low\|normal\|high]` | Send an arbitrary message through the configured alerting backend(s). Used internally by `update.sh --check-only`. |
| `--reconcile [--json]` | Compare CrowdSec's currently active decisions against this proxy's report cache and report any that are missing (see "CrowdSec decision reconciliation" below). Suitable for a periodic timer. |

## Endpoints

Besides the CrowdSec webhook target (`POST /`), the proxy exposes two read-only endpoints on the same local port:

- **`GET /health`** — JSON status: `{"status", "version", "dry_run", "uptime_seconds", "cache_reports_tracked", "pending_escalations", "pending_retries", "abuseipdb_quota"}`
- **`GET /metrics`** — Prometheus text format: `abuseipdb_proxy_reports_sent_total`, `abuseipdb_proxy_reports_suppressed_total`, `abuseipdb_proxy_reports_failed_total`, `abuseipdb_proxy_reports_ignored_private_total`, `abuseipdb_proxy_reports_quota_reserved_total`, `abuseipdb_proxy_reports_whitelisted_total`, plus gauges for pending escalations/retries, uptime, and AbuseIPDB quota remaining/limit (once known)

Both are **off by default** and bound to `127.0.0.1` only once enabled. Turn them on with `ABUSEIPDB_ENABLE_HEALTH=true` / `ABUSEIPDB_ENABLE_METRICS=true`.

**Grafana**: a ready-made dashboard for `/metrics` lives in [`Grafana/dashboard.json`](Grafana/dashboard.json) — report rates, pending escalations/retries, quota, uptime. See [`Grafana/README.md`](Grafana/README.md) for the Prometheus scrape config and import steps.

## Alerting (optional)

If you want to be notified when something actually needs attention — not on every report, only when the proxy gives up on a report after exhausting all retries, or when it can't write its cache file — configure any combination of:

- **[Gotify](https://gotify.net/)**: set `ABUSEIPDB_GOTIFY_URL` and `ABUSEIPDB_GOTIFY_TOKEN`
- **[ntfy](https://ntfy.sh/)**: set `ABUSEIPDB_NTFY_URL` (and `ABUSEIPDB_NTFY_TOKEN` if the topic is protected)
- **Slack**: set `ABUSEIPDB_SLACK_WEBHOOK_URL` to an [Incoming Webhook](https://api.slack.com/messaging/webhooks) URL
- **Discord**: set `ABUSEIPDB_DISCORD_WEBHOOK_URL` to a channel webhook URL
- **[Matrix](https://matrix.org/)**: set `ABUSEIPDB_MATRIX_HOMESERVER_URL`, `ABUSEIPDB_MATRIX_ACCESS_TOKEN`, and `ABUSEIPDB_MATRIX_ROOM_ID` (all three required — posts as a bot user via the Client-Server API, no webhook needed; invite the bot account into the room first)
- **Telegram**: set `ABUSEIPDB_TELEGRAM_BOT_TOKEN` (from [@BotFather](https://t.me/BotFather)) and `ABUSEIPDB_TELEGRAM_CHAT_ID`
- **[Home Assistant](https://www.home-assistant.io/)**: set `ABUSEIPDB_HOMEASSISTANT_URL` and `ABUSEIPDB_HOMEASSISTANT_TOKEN` (a [Long-Lived Access Token](https://www.home-assistant.io/docs/authentication/#your-account-profile) from your HA user profile — calls `notify.notify` over HA's REST API natively, no bridge needed; set `ABUSEIPDB_HOMEASSISTANT_NOTIFY_SERVICE` to target a specific device instead of the generic notify service)
- **Generic webhook**: set `ABUSEIPDB_WEBHOOK_URL` for anything else (receives a JSON POST with `name`/`message`/`priority`)

Each backend activates itself automatically as soon as its required variable(s) are set — no separate "enable" flag. Multiple backends can run at once. The display name shown in notifications defaults to `CrowdSec Smart AbuseIPDB Proxy` and is customizable via `ABUSEIPDB_NOTIFY_NAME`.

Test your setup without waiting for a real failure:
```bash
python3 abuseipdb_proxy.py --test-notify
```

## CrowdSec decision reconciliation (optional)

The normal live path (CrowdSec → `abuseipdb.yaml` webhook → this proxy) can miss a report if the proxy happens to be down, restarting, or briefly unreachable when CrowdSec fires the notification — CrowdSec doesn't retry failed webhook deliveries itself. `--reconcile` is a catch-up job for exactly that gap: it asks CrowdSec's local API (the same one bouncers use) for every currently active ban decision, and reports any IP that's missing from this proxy's own cache.

Requires a CrowdSec bouncer API key:
```bash
cscli bouncers add abuseipdb-proxy-reconcile
```
Set the key it prints as `ABUSEIPDB_CROWDSEC_BOUNCER_KEY`, then run:
```bash
python3 abuseipdb_proxy.py --reconcile
```

It goes through the exact same dedup/escalation/quota-reservation/whitelist logic as a live alert — an IP already in the cache is left alone. Categories and severity are derived from the CrowdSec decision's own scenario name, using the same mapping `abuseipdb.yaml`'s template uses (kept in sync and cross-checked by `tests/test_scenario_mapping.py`) — a reconciled report is categorized exactly like the live alert would have been. Only decisions with no scenario name at all (added manually via `cscli decisions add`) fall back to the fixed `ABUSEIPDB_RECONCILE_SEVERITY`/`ABUSEIPDB_RECONCILE_CATEGORIES`. Either way, the comment on a reconciled report says explicitly that it's a catch-up run, so it's obvious in your AbuseIPDB history which reports came from a live detection versus reconciliation.

Suitable for a periodic timer — `abuseipdb-proxy-reconcile.service`/`.timer` (hourly by default) ship in this repo and get offered by `install.sh` once a bouncer key is configured. If it finds and reports anything missing, it also sends a message through your configured alerting backend(s) — otherwise a periodic catch-up job silently doing its job is easy to forget even exists.

## Version history

Kept in [CHANGELOG.md](CHANGELOG.md) rather than duplicated here — this README was getting unwieldy with every release's full changelog inlined. `CHANGELOG.md` has the complete, dated history from v1.1.0 onward.

## Files in this repo

```
crowdsec-smart-abuseipdb/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml               # CI: shellcheck + Python syntax check + pytest + Docker build/smoke-test
│   │   ├── release.yml          # Auto-creates a GitHub Release from CHANGELOG.md on tag push
│   │   └── docker-publish.yml   # Builds & pushes multi-arch images to GHCR when that Release is published
│   └── ISSUE_TEMPLATE/         # Bug report / feature request forms
├── .gitignore
├── .dockerignore                # Applies to the build context (repo root) even though the Dockerfile itself lives in Docker/
├── Docker/                      # Everything Docker-related, kept separate from the bare-metal install below
│   ├── Dockerfile               # Alpine-based image, zero third-party dependencies
│   ├── docker-compose.yml
│   └── docker-compose.env.example  # Copy to docker-compose.env and fill in
├── abuseipdb_proxy.py          # The proxy itself
├── abuseipdb-proxy.env.example # Config template
├── abuseipdb-proxy.service     # systemd unit
├── abuseipdb-proxy-update-check.service  # Optional: daily update-check (used by the timer below)
├── abuseipdb-proxy-update-check.timer    # Optional: schedules the update check
├── abuseipdb-proxy-vacuum.service        # Optional: SQLite cache vacuum (used by the timer below)
├── abuseipdb-proxy-vacuum.timer          # Optional: schedules the weekly vacuum
├── abuseipdb-proxy-backup.service        # Optional: daily cache backup (used by the timer below)
├── abuseipdb-proxy-backup.timer          # Optional: schedules the daily backup
├── abuseipdb-proxy-reconcile.service     # Optional: CrowdSec decision reconciliation (used by the timer below)
├── abuseipdb-proxy-reconcile.timer       # Optional: schedules the hourly reconciliation run
├── Grafana/
│   ├── dashboard.json           # Import-ready dashboard for /metrics
│   └── README.md                # Scrape config + import steps
├── abuseipdb.yaml              # CrowdSec HTTP notification config
├── install.sh                  # Installer
├── update.sh                   # Checks for and applies updates (or just checks, see --check-only)
├── uninstall.sh                 # Removes everything install.sh created
├── tests/                       # pytest suite, run in CI
├── pytest.ini
├── .coveragerc
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE                     # MIT
├── README.md                   # English
└── README.de.md                # German
```

## Known limitations

- No authentication on the local port by default — not a concern as long as it only listens on `127.0.0.1` (the Docker default of `0.0.0.0` is fine specifically because it stays inside Docker's own network isolation, see "Docker" above). For setups where that boundary is less clean-cut, `ABUSEIPDB_ALLOWED_SOURCE_IPS` and `ABUSEIPDB_SHARED_SECRET` add optional extra layers — see "Configuration" above.
- The 15-minute default window is configurable per severity tier (`ABUSEIPDB_REPORT_WINDOW_*`) and, since v2.5.0, per category (`ABUSEIPDB_REPORT_WINDOW_CATEGORIES`) — but still not per individual IP.
- The default SQLite cache scales comfortably to a large report history; the JSON backend (`ABUSEIPDB_CACHE_BACKEND=json`) is fine for typical CrowdSec traffic volumes but, being a flat file rewritten on every save, isn't built for extremely high cardinality (tens of thousands of distinct IPs tracked at once).

## Contributing

Issues and PRs welcome — especially ideas for a persistent `pending_timers` store, additional severity categories, or remote backup destinations for `--backup`.
