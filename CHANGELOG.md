# Changelog

All notable changes to this project are documented here.

## [2.8.0] - Concurrent request handling, precise reconciliation categorization

Purely additive/fixes — no breaking changes.

### Fixed
- **Whitelist check (and everything else) no longer blocks concurrent requests**: switched from `http.server.HTTPServer` (handles one request at a time) to `http.server.ThreadingHTTPServer` (`daemon_threads=True`, `request_queue_size=128` — raised from the default of 5, since CrowdSec can fire several alerts in quick succession and a real burst could otherwise get connections refused before a thread even gets spun up to accept them). A slow `ABUSEIPDB_SKIP_WHITELISTED` `/v2/check` call — or any other slow request — used to delay every other alert queued behind it; now each connection gets its own thread. Removed the corresponding "known limitation" from the README.
- **Two pre-existing race conditions**, both check-then-act patterns that ran partly outside their lock (latent since whenever they were introduced — more likely to actually manifest now that requests run concurrently by default):
  - `_switch_to_fallback_key()`: the "already on the fallback?" check ran *before* acquiring `_active_key_lock`, so multiple concurrent 429s could each pass the check and each think they performed the switch, each firing its own notification. Fixed with a proper double-checked-locking pattern (check happens under the lock now).
  - The daily quota-warning notification: `_quota_warned_date`'s check-and-set ran *outside* `quota_lock`, with the same failure mode — concurrent report threads breaching the threshold at once could each fire the "quota is getting low" notification. Fixed the same way.
- **`_schedule_pending()` no longer relies on its caller already holding `lock`**: it previously assumed this implicitly (true only because its one call site happened to hold the lock already) rather than acquiring it itself, which would have been a silent reintroduction of the exact class of bug above the moment anyone called it from a new code path. `lock` is now an `RLock` (reentrant — needed since `process_alert()` calls `_schedule_pending()` from inside its own `with lock:` block) and `_schedule_pending()` acquires it explicitly.
- **`--reconcile` now categorizes exactly like a live alert would have**: previously used a fixed `ABUSEIPDB_RECONCILE_SEVERITY`/`_CATEGORIES` for every reconciled report regardless of what CrowdSec actually detected. Now derives categories from the CrowdSec decision's own `scenario` field (now included in what `fetch_crowdsec_active_decisions()` returns) via a new `categories_for_scenario()` — a Python port of `abuseipdb.yaml`'s Go-template if/else-if chain — and severity via the existing `get_severity()`. `ABUSEIPDB_RECONCILE_SEVERITY`/`_CATEGORIES` remain as a fallback for decisions with no scenario name at all (e.g. added manually via `cscli decisions add`). `tests/test_scenario_mapping.py` parses `abuseipdb.yaml` itself and cross-checks it against the Python rule list, so the two can't silently drift apart.
- `ci.yml`'s systemd-unit-syntax check was missing `abuseipdb-proxy-backup.service`/`.timer` and `abuseipdb-proxy-reconcile.service`/`.timer` (both added in v2.6.0) — CI wasn't actually validating either. Added.

### Added
- `tests/test_threading_server.py`: 4 real integration tests that start the actual `ThreadingHTTPServer` and fire concurrent HTTP requests at it — dedup correctness under real concurrency for both the same IP and many different IPs, the slow-whitelist-check-doesn't-block-others fix specifically, and a burst of malformed request bodies not taking the server down. `tests/test_scenario_mapping.py`: 23 tests for the new reconciliation categorization, including the yaml/Python consistency check. Plus 2 new regression tests for the race-condition fixes. 314 total.

## [2.7.0] - Secrets-from-file support, reconciliation notifications, README cleanup

Purely additive — no breaking changes.

### Added
- **`{VARIABLE}_FILE` secrets convention**: every secret-like config value (`ABUSEIPDB_API_KEY`, `ABUSEIPDB_API_KEY_FALLBACK`, `ABUSEIPDB_CROWDSEC_BOUNCER_KEY`, `ABUSEIPDB_SHARED_SECRET`, and every notification backend token/webhook URL) now also accepts a `{VARIABLE}_FILE` override pointing at a file to read the value from instead — the Docker/Podman secrets convention, so a value can come from a mounted secret or a secrets-manager-backed file instead of sitting in plain text in `docker-compose.env`/`abuseipdb-proxy.env`. If both are set, `_FILE` wins. Implemented as a new `_get_secret()` helper that deliberately never calls `log()` for its own error reporting (a bare `sys.stderr.write`, matching the existing `_validated_pragma()` right above it) — `ABUSEIPDB_API_KEY` is resolved at module-import time before `log()` itself is even defined, so anything reachable from that code path has to stay independent of it. `docker-compose.yml` got a commented example bind-mount for using this.
- **Reconciliation notifications**: `--reconcile` now sends a message through the configured alerting backend(s) whenever it finds and reports anything missing (previously log-only) — capped to the first 20 IPs plus a "+N more" suffix so a large catch-up run doesn't blow past a backend's message-length limit.

### Changed
- **README.md/README.de.md**: removed the per-version `## New in vX.Y.Z` sections (they'd made the README unwieldy) in favor of a short "Version history" pointer to this file, which already had the same information in more detail. No content lost, just no longer duplicated in two places that could drift apart.
- Fixed a stale `python:3.12-alpine` mention in both READMEs' Docker section prose (the `Dockerfile` itself moved to `3.13-alpine` via a Dependabot merge a few versions back; the prose just hadn't caught up).
- `tests/test_secrets_file.py`: 11 new tests for `_get_secret()`. `tests/test_reconcile_scrub_fallback.py`: 3 new tests for the reconciliation notification. 282 total.

## [2.6.0] - Comment scrubbing, fallback API key, CrowdSec decision reconciliation

Purely additive — no breaking changes. All three features are opt-in and off by default.

### Added
- **`ABUSEIPDB_COMMENT_SCRUB_PATTERNS` / `ABUSEIPDB_COMMENT_SCRUB_REPLACEMENT`**: redacts matches of one or more semicolon-separated regexes from the comment text before it's sent to AbuseIPDB — whose comments are public. Applied once, right before the actual API call, so retries stay consistent. Invalid regexes are logged and skipped, not fatal.
- **`ABUSEIPDB_API_KEY_FALLBACK`**: a second AbuseIPDB API key to switch to once the primary key's daily quota is exhausted. Detected via an HTTP 429 from `/v2/report`; switches immediately and retries the same report with the fallback key rather than waiting out the normal retry backoff (which for a daily-quota 429 could be hours). Switches back to the primary automatically the first time a new UTC day is observed. New `abuseipdb_proxy_using_fallback_key` gauge, exposed via `/metrics` (only when a fallback key is configured).
- **`--reconcile`** (new CLI flag) + `ABUSEIPDB_CROWDSEC_LAPI_URL` / `ABUSEIPDB_CROWDSEC_BOUNCER_KEY` / `ABUSEIPDB_RECONCILE_SEVERITY` / `ABUSEIPDB_RECONCILE_CATEGORIES`: queries CrowdSec's local API (the same one bouncers use, needs a key from `cscli bouncers add`) for currently active ban decisions, and reports any IP missing from this proxy's own report cache — catches reports lost to proxy downtime or a dropped notification. Routes through the same `process_alert()` as a live alert, so dedup/escalation/quota-reservation/whitelist logic all still applies. `process_alert()` now returns the background thread it started (`None` if none was needed), which `--reconcile` joins before exiting so a one-shot CLI run can't kill an in-flight send. New `abuseipdb-proxy-reconcile.service`/`.timer` (hourly by default), wired into `install.sh`/`uninstall.sh` alongside the existing vacuum/backup timers — offered only when a bouncer key is already configured.
- `tests/test_reconcile_scrub_fallback.py`: 18 new tests covering all three features — 268 total.
- `--check-config` validates the new options: scrub-pattern parsing, a fallback key identical to the primary (pointless), and whether reconciliation is configured.

## [2.5.0] - Per-category windows, quota reservation, local-port access control, whitelist pre-check

Purely additive — no breaking changes. All four features are opt-in and off by default.

### Added
- **`ABUSEIPDB_REPORT_WINDOW_CATEGORIES`**: comma-separated `category=seconds` overrides (e.g. `16=1800,20=3600`) for specific AbuseIPDB categories, finer-grained than the existing per-severity windows (`ABUSEIPDB_REPORT_WINDOW_LOW`/`_MEDIUM`/`_HIGH`). Wins over the severity window when a reported category matches; the smallest matching window applies if more than one does.
- **`ABUSEIPDB_QUOTA_RESERVE_MEDIUM` / `ABUSEIPDB_QUOTA_RESERVE_HIGH`**: reserve part of the day's remaining AbuseIPDB quota for higher-severity findings, holding back lower-severity reports once the remaining quota (tracked from the API's own rate-limit headers) drops to or below the configured threshold. Applies at every point a report could be sent — immediate reports, immediate escalations, and delayed escalations when their timer fires. Only takes effect once the proxy has actually seen a remaining-quota count from AbuseIPDB; never blocks anything based on a guess. New `abuseipdb_proxy_reports_quota_reserved_total` counter, exposed via `/metrics`.
- **`ABUSEIPDB_ALLOWED_SOURCE_IPS` / `ABUSEIPDB_SHARED_SECRET`**: optional extra layers on top of `ABUSEIPDB_LISTEN_ADDRESS` for setups where the loopback-only/Docker-network boundary is less clean-cut. The allowlist accepts comma-separated IPs/CIDRs; the shared secret is checked via an `X-Proxy-Secret` header (constant-time comparison via `hmac.compare_digest`) — `abuseipdb.yaml` has a commented-out example of setting it. Requests failing either check get a 403, logged with the source IP.
- **`ABUSEIPDB_SKIP_WHITELISTED`**: skips reporting IPs that AbuseIPDB's own `/v2/check` endpoint marks as `isWhitelisted` (e.g. well-known crawlers/CDNs that opted in). Off by default: `/v2/check` consumes its own daily quota separate from `/v2/report`, and the check is a synchronous network call on the request path — mitigated by an in-memory per-IP cache (`ABUSEIPDB_WHITELIST_CACHE_TTL`, default 86400s). Fails open (reports anyway) on any network error. New `abuseipdb_proxy_reports_whitelisted_total` counter, exposed via `/metrics`.
- `tests/test_new_features.py`: 22 new tests covering all four features — 250 total.
- `--check-config`/`--doctor` validate the new options: allowlist/secret parsing, quota-reserve threshold ordering (`MEDIUM` should be `>=` `HIGH`), and a note when the whitelist check is enabled but has no effect under `--dry-run`.

## [2.4.0] - CI supply-chain hardening, Dependabot, SECURITY.md, logrotate

Purely additive/hardening — no breaking changes.

### Added
- **`SECURITY.md`**: how to report a vulnerability privately (via GitHub's private reporting, not a public issue), what's in scope, and supported versions.
- **`.github/dependabot.yml`**: keeps the newly SHA-pinned GitHub Actions, the `python:3.12-alpine` base image in `Docker/Dockerfile`, and `tests/requirements.txt` current automatically, opening a PR for each.
- **`abuseipdb-proxy.logrotate`**: an optional logrotate config for anyone redirecting the proxy's own output to a plain file instead of relying on journald/Docker's log driver (both of which already rotate on their own, and remain the default either way). Not installed by `install.sh` — opt-in only, since it doesn't apply to the default setup.

### Changed
- **All GitHub Actions across every workflow are now pinned to a full commit SHA** (`actions/checkout@11d5960...` with a `# v4.4.0` comment) instead of a mutable tag like `@v4` — closes the same supply-chain gap that let the March 2025 `tj-actions/changed-files` compromise leak secrets from thousands of repos: a tag can be repointed to different code later (by the maintainer or an attacker who compromises their account), a commit SHA can't. All 9 third-party actions used across `ci.yml`/`release.yml`/`docker-publish.yml` are covered. Dependabot (above) keeps these pins current going forward.

## [2.3.0] - Telegram/Home Assistant backends, --check-config, --doctor, --backup, Grafana, signed images

Purely additive — no breaking changes.

### Added
- **Two new alerting backends**: **Telegram** (`ABUSEIPDB_TELEGRAM_BOT_TOKEN`/`_CHAT_ID`) and native **Home Assistant** (`ABUSEIPDB_HOMEASSISTANT_URL`/`_TOKEN`/`_NOTIFY_SERVICE`, calls `notify.*` directly over HA's REST API, no bridge needed) — eight backends total alongside Gotify/ntfy/Slack/Discord/Matrix/generic webhook.
- **`--check-config [--json]`**: validates the whole configuration end-to-end (API key, cache path, alerting backends, timing settings) with no network access and no changes made — catches a half-configured backend or a typo'd env var before it fails silently later. Exit code 1 if anything failed.
- **`--doctor [--no-network] [--json]`**: everything `--check-config` covers, plus systemd service status, file permissions on the key/cache, whether CrowdSec's `profiles.yaml` actually wires this notification up, cache readability, and (unless `--no-network`) whether api.abuseipdb.com is reachable. Bare-metal-specific checks skip themselves cleanly when they don't apply (e.g. in Docker).
- **`--backup [DIR] [--json]`**: writes a timestamped, portable JSON snapshot of the cache into DIR (default: a `backups/` folder next to the cache file), then prunes old backups beyond `ABUSEIPDB_BACKUP_RETENTION` (default 14, keeps the most recent N). New optional daily systemd timer, `abuseipdb-proxy-backup.service`/`.timer`, offered by `install.sh` and removed by `uninstall.sh`.
- **Grafana dashboard**: `Grafana/dashboard.json` (import-ready, Prometheus datasource) covering report rates, pending escalations/retries, AbuseIPDB quota, and uptime — see `Grafana/README.md` for the scrape config and import steps.
- **Signed, SBOM'd Docker images**: `docker-publish.yml` now signs every image keylessly with [cosign](https://github.com/sigstore/cosign)/Sigstore (GitHub OIDC, no key management) and generates+attaches an SPDX SBOM, both by digest. See "Docker" in the README for the `cosign verify` command.
- **Docker Compose files attached to GitHub Releases**: `Docker/docker-compose.yml` and `Docker/docker-compose.env.example` are now uploaded as downloadable Release assets, so someone can grab just those two files without cloning the repo.
- `tests/`: coverage extended for all of the above — 228 tests total.

### Changed
- **`Docker/docker-compose.yml` no longer offers a local `build:` option** — now that images are genuinely published, it only ever pulls from GHCR. Contributors testing a Dockerfile change build manually per `CONTRIBUTING.md` instead.
- **`Docker/docker-compose.env.example` now mirrors every environment variable the bare-metal install supports** (previously a small subset), for full configuration freedom in the Docker setup too — only the genuinely important ones active by default, everything else commented out at its default value.
- A typo'd `ABUSEIPDB_CACHE_BACKEND` (e.g. `sqllite`) previously fell through silently to the JSON code path against a SQLite-flavored filename (or vice versa) — meaning reads/writes of garbage with no warning. Now validated at import time with a fallback to `sqlite` and a clear stderr warning, same pattern as the existing SQLite PRAGMA validation.

## [2.2.0] - GHCR image publishing, Docker/ folder, startup banner

Purely additive — no breaking changes for the bare-metal install. Anyone who already deployed the Docker setup from v2.1.0 needs to adjust paths — see below.

### Added
- **Published Docker images**: `docker-publish.yml` builds and pushes multi-arch (`linux/amd64`, `linux/arm64`) images to `ghcr.io/pumbalp/crowdsec-smart-abuseipdb-proxy` automatically whenever a GitHub Release is published (i.e. right after `release.yml` creates one from a tag push), tagged `X.Y.Z`/`X.Y`/`X`/`latest`/`sha-<commit>`. `docker-compose.yml` now pulls that published image by default instead of building locally — `docker compose up -d` alone is enough, no `--build` needed. Local `build:` is still available, just commented out.
- **Set and forget**: `docker-compose.yml` includes a commented-out, opt-in [Watchtower](https://containrrr.dev/watchtower/) service, scoped to just this container via a label. Defaults to notify-only (`WATCHTOWER_MONITOR_ONLY=true`) through the same alerting backend already configured for the proxy — matches `update.sh --check-only`'s never-auto-apply-unattended philosophy; delete one line to switch to full auto-apply instead.
- **Startup banner**: a boxed ASCII summary printed once at service boot (not for one-shot CLI flags like `--version`/`--stats`), showing version, mode (dry-run/live), cache backend, listen address, and which alerting backends are active. Skipped automatically in `ABUSEIPDB_LOG_FORMAT=json` mode, since it has no sensible structured representation.

### Changed
- **All Docker-related files moved into a `Docker/` folder** (`Docker/Dockerfile`, `Docker/docker-compose.yml`, `Docker/docker-compose.env.example`), separated from the bare-metal install at the repo root. `.dockerignore` stays at the repo root (it applies to the build context, which is still the repo root — the Dockerfile needs `abuseipdb_proxy.py` from there). If you deployed the Docker setup from v2.1.0: `cd Docker`, re-copy your API key into a new `docker-compose.env` there (or move the old one), and run `docker compose up -d` from inside `Docker/` going forward. CI and the new publish workflow build with `-f Docker/Dockerfile` from a repo-root context.

### Fixed
- The initial GHCR publish workflow derived the image path from `${{ github.repository }}`, which preserves this repo's actual mixed-case name (`PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy`) — but Docker/OCI registries require an all-lowercase repository path, so every push would have failed outright. Fixed before the workflow ever ran for real by explicitly lowercasing it to match what `docker-compose.yml` actually pulls (`ghcr.io/pumbalp/crowdsec-smart-abuseipdb-proxy`).

## [2.1.0] - Structured logging, quota tracking, cache export/import, SQLite vacuum, Docker

Purely additive — no breaking changes, existing installs need no action.

### Added
- **Structured JSON logging**: `ABUSEIPDB_LOG_FORMAT=json` switches every log line to a single JSON object (timestamp/level/message plus extra structured fields depending on the event — IP, categories, HTTP status, retry counts, quota numbers, ...) instead of the traditional plain-text line, for Loki/ELK/Graylog and friends. `text` (unchanged) stays the default.
- **AbuseIPDB quota tracking**: the API's own `X-RateLimit-Limit`/`X-RateLimit-Remaining` response headers are now read on every report (success or failure) and exposed via `/health` and `/metrics`. A one-time-per-day notification fires through your configured alerting backend when the remaining quota drops to or below `ABUSEIPDB_QUOTA_WARN_THRESHOLD` (default 50) — a heads-up before you actually run out mid-day, not after. Also persisted to a small sidecar file next to the cache, so `--stats` (a separate one-off process) can see it too, not just the running service.
- **`--stats [--json] [--stats-limit N]`**: a snapshot of what's currently in the cache — recent reports with a severity breakdown, pending escalations, queued retries, AbuseIPDB quota — without needing `/health`/`/metrics` enabled. Reads the cache directly, so it works the same against either backend.
- **`--export [PATH]` / `--import PATH`**: portable, backend-agnostic JSON snapshots of the cache (reports/pending/retry_queue), for backups or moving history between hosts regardless of which cache backend (json/sqlite) is active on either end. `--import` prompts for confirmation (replaces the current cache entirely) unless `-y`/`--yes` is also given.
- **`--vacuum`**: prunes stale reports and runs SQLite's `VACUUM` to reclaim disk space freed by the continuous DELETE+INSERT churn every cache save does under the hood. No-op (not an error) on the JSON backend. New optional weekly systemd timer, `abuseipdb-proxy-vacuum.service`/`.timer`, offered by `install.sh` when the SQLite backend is in use and removed by `uninstall.sh`.
- **Docker**: a `Dockerfile` (small `python:3.12-alpine` build — the proxy has zero third-party Python dependencies) and `docker-compose.yml`, as an alternative to `install.sh` for containerized setups. New `ABUSEIPDB_LISTEN_ADDRESS` (default `127.0.0.1`, unchanged for bare-metal) makes the bind address configurable for this. CI now builds the image and smoke-tests it (including verifying `sqlite3` actually works in the image) on every push. Multi-arch (amd64/arm64) images are published to GHCR automatically on every GitHub Release via the new `docker-publish.yml` workflow, tagged `X.Y.Z`/`X.Y`/`X`/`latest`/`sha-<commit>`; `docker-compose.yml` pulls the published image by default (local `build: .` still available, just commented out). Includes an opt-in Watchtower service block for "set and forget" updates — notify-only by default, matching `update.sh --check-only`'s never-auto-apply philosophy.
- `tests/`: coverage extended for all of the above (structured logging, quota parsing/warning/cross-process persistence, export/import round-trips and validation, vacuum, stats, listen address) — 149 tests total.

## [2.0.0] - SQLite is now the default cache, plus update-check timer, test suite, dynamic release badge

### Breaking changes
- **The default cache backend changed from a single JSON file to SQLite.** A real database (`reports`/`pending`/`retry_queue` tables, WAL journal + NORMAL sync by default — a good, SSD-friendly balance of speed and crash-safety) replaces the JSON file as the default, mainly because it scales better once the report history gets large and it's directly queryable with `sqlite3`. **If you're upgrading from v1.x, this is automatic and non-destructive**: the first time the proxy runs, it detects the existing `cache.json` next to where the new `cache.db` would go, imports it into SQLite, and renames it to `cache.json.migrated` (never deleted). No action needed, no history lost — but do read the log line it prints on that first run. Prefer the old behavior? Set `ABUSEIPDB_CACHE_BACKEND=json`. Storage tuning (journal mode / sync) is configurable via `ABUSEIPDB_SQLITE_JOURNAL_MODE` / `ABUSEIPDB_SQLITE_SYNCHRONOUS` for storage that isn't SSD-like (e.g. an SD card).

### Added
- `update.sh --check-only`: checks for updates without applying them, then sends a notification through whatever alerting backend is already configured (Gotify/ntfy/Slack/Discord/Matrix/webhook) if one is found — no automatic changes to a running install. Add `--json` for a single-line machine-readable result instead, for feeding into your own tooling. Backed by two new optional systemd units, `abuseipdb-proxy-update-check.service`/`.timer`, offered by `install.sh` (daily, `Persistent=true`, ~1h randomized delay) and removed by `uninstall.sh`.
- `abuseipdb_proxy.py --notify MESSAGE [--notify-priority low|normal|high]`: sends an arbitrary message through the configured alerting backend(s) and exits. Used internally by `update.sh --check-only`; `--test-notify` now shares the same code path.
- Three new alerting backends: **Slack** (`ABUSEIPDB_SLACK_WEBHOOK_URL`), **Discord** (`ABUSEIPDB_DISCORD_WEBHOOK_URL`), and **Matrix** (`ABUSEIPDB_MATRIX_HOMESERVER_URL`/`_ACCESS_TOKEN`/`_ROOM_ID`), alongside the existing Gotify/ntfy/generic webhook.
- `tests/`: a real `pytest` suite (83 tests, with coverage reporting) covering severity mapping, private/CGNAT IP filtering, cache persistence for both backends (including legacy JSON-format upgrades and the new JSON→SQLite migration), the core dedup/escalation decision logic, retry/backoff behavior, all six notification backends, and the CLI — replacing the ad-hoc throwaway test scripts used during development of earlier versions. Runs in CI on every push/PR.
- Dynamic release badge in the README (`shields.io`, pulled live from the GitHub API) next to the existing CI badge.

### Changed
- CI now also runs ShellCheck against `update.sh` and `uninstall.sh` (previously only `install.sh` was linted), validates the new update-check unit files, and reports test coverage in the job summary.

## [1.5.0] - Version tracking, update.sh & uninstall.sh

### Added
- The proxy now knows its own version: `--version` prints it, `GET /health` includes it, `GET /metrics` exposes it as `abuseipdb_proxy_info{version="..."}`.
- `update.sh`: checks for new commits on `origin/main`, refuses to run if the checkout has uncommitted local changes, shows what changed (including the matching `CHANGELOG.md` section if the version bumped), then pulls and re-runs `install.sh`. Safe to run repeatedly — does nothing if already up to date. Use `-y`/`--yes` to skip the confirmation prompt.
- `uninstall.sh`: removes everything `install.sh` created (service, binary, config, cache, CrowdSec notification), with an option to keep the API key and cache if you might reinstall later. Leaves `/etc/crowdsec/profiles.yaml` untouched, same reasoning as `install.sh`.

## [1.4.0] - Start notifications & automated releases

### Added
- `ABUSEIPDB_NOTIFY_ON_START`: optional low-priority notification via any configured alerting backend whenever the proxy starts — useful to confirm an update actually restarted the service.
- `.github/workflows/release.yml`: pushing a `vX.Y.Z` tag now automatically creates a GitHub Release, with title and notes pulled directly from the matching `CHANGELOG.md` section (not auto-generated from commits).

## [1.3.0] - Configurable alerting, observability & log volume control

### Added
- Configurable alerting: optional Gotify / ntfy / generic webhook notifications, triggered when a report permanently fails after all retries, or when the cache file can't be written. Each backend auto-activates once its URL (and token, where needed) is set — no separate enable flag. Display name customizable via `ABUSEIPDB_NOTIFY_NAME`. Test with `--test-notify`.
- `GET /health` and `GET /metrics` (Prometheus format) endpoints for basic observability: uptime, pending escalations/retries, cache size, and counters for sent/suppressed/failed/ignored reports. Both off by default (opt in via `ABUSEIPDB_ENABLE_HEALTH` / `ABUSEIPDB_ENABLE_METRICS`).
- Private/reserved IP filtering: RFC1918, loopback, link-local, and CGNAT (100.64.0.0/10, which also covers Tailscale) addresses are skipped automatically before reaching the dedup logic. Extend via `ABUSEIPDB_IGNORE_IPS`, disable built-in filtering via `ABUSEIPDB_IGNORE_PRIVATE=false`.
- Log volume control for high-traffic setups (e.g. honeypots): a periodic summary log line (`ABUSEIPDB_SUMMARY_INTERVAL`, default 300s) replaces per-event logging by default. Per-event detail available via `ABUSEIPDB_VERBOSE_LOGGING=true`. `abuseipdb-proxy.service` also gained `LogRateLimitIntervalSec`/`LogRateLimitBurst` as an independent safety net.

## [1.2.0] - Broader category coverage, automatic retries, per-severity windows

### Added
- Severity map now covers all 23 official AbuseIPDB categories (was 8).
- `abuseipdb.yaml` recognizes more CrowdSec scenario name patterns (SQLi, XSS, path traversal, open proxy, backdoors, generic `-bf` suffixes, `CVE-...` identifiers, etc.).
- Automatic retry for failed reports (network errors, AbuseIPDB downtime, 429 rate limits), honoring the `Retry-After` header when present. Configurable via `ABUSEIPDB_MAX_RETRIES` and `ABUSEIPDB_RETRY_DELAY`. Retries are persisted and survive a restart.
- Per-severity report windows: `ABUSEIPDB_REPORT_WINDOW_LOW` / `_MEDIUM` / `_HIGH`.

### Fixed
- Scenario matching in `abuseipdb.yaml` is now case-insensitive (via Sprig's `lower`). Previously an uppercase `CVE-...` scenario name fell through to the generic category instead of being recognized as an exploit attempt.

### Changed
- Cache file format gained a `retry_queue` section. Older cache files (v1.0.0 flat format, v1.1.0 without `retry_queue`) are read and upgraded automatically.

## [1.1.1] - Installer restart fix

### Fixed
- `install.sh` now explicitly `restart`s the service instead of `enable --now`. If `abuseipdb-proxy.service` was already running (e.g. when re-running the installer to apply an update), `start` was a no-op and the old code kept running silently until a manual `systemctl restart`.
- `install.sh` and `abuseipdb_proxy.py` now have the executable bit set in the repository, so `sudo ./install.sh` works right after `git clone` without needing `chmod +x` first.

## [1.1.0] - Persistent pending reports & dry-run mode

### Added
- Persistent pending-report store: delayed escalation reports survive a proxy restart instead of being dropped. They're written to the cache file when scheduled and re-armed on startup.
- `--dry-run` flag / `ABUSEIPDB_DRY_RUN` env var: log what would be reported without calling the AbuseIPDB API.

### Changed
- Cache file format now has `reports` and `pending` sections. Old flat-format cache files from v1.0.0 are read and upgraded automatically.

## [1.0.0] - Initial release

Initial public release.

### Added
- Deduplicated, severity-aware forwarding of CrowdSec alerts to AbuseIPDB
- Configurable report window (default: 15 minutes) to avoid API rate limits
- Persistent cache under `/var/lib/abuseipdb-proxy`
- systemd service with hardening (`NoNewPrivileges`, `ProtectSystem=strict`)
- API key stored separately via `EnvironmentFile` (not in the unit file)
- One-command installer (`install.sh`)
- README available in English and German
