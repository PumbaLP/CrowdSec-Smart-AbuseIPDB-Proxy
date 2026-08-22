# Changelog

All notable changes to this project are documented here.

## [3.0.4] - Follow-up hardening pass after 3.0.3's release

A further read-through audit of the entire file after 3.0.3 shipped, this time focused specifically on lock contention/scaling and on unvalidated input (env vars and request fields) that could cause a crash or an unbounded loop instead of failing safely. Four issues found, all fixed and covered by regression tests (each reproduced against the pre-fix code first, not just asserted against the fix). No breaking changes.

### Fixed
- **The hourly stale-report sweep (`_maybe_sweep_stale_reports()`) ran its `DELETE` while holding the same global `lock` every single incoming alert needs**, and `reports.time` had no index, meaning that DELETE was an unindexed full-table scan. On an installation with a large `reports` table, this meant every concurrent in-flight alert across every IP in the system could get stuck waiting once an hour for an unrelated maintenance operation to finish. Fixed two ways: added `CREATE INDEX IF NOT EXISTS idx_reports_time ON reports(time)` (additive, safe on existing databases), and moved the sweep's `DELETE` entirely outside the main `lock`, guarded instead by a new dedicated `_sweep_lock` that only protects the tiny "is a sweep due, and if so, claim it" check — not the DELETE itself. A stale-report sweep doesn't depend on, or affect, any single IP's live dedup decision, so there's no correctness reason for it to block on the same lock.
- **A non-string `"ip"` field in a POST body was silently accepted and processed as a real address instead of being rejected.** `ipaddress.ip_address()` accepts an int (interpreting it as a packed address) rather than raising, so `{"ip": 16909060, ...}` used to sail straight through `is_ignored_ip()`/`is_whitelisted()` and get treated as a real report target — worse, it wasn't even correctly decoded to the address it represents, it was stored as the literal integer. Fixed with an explicit `isinstance(ip, str)` check; `categories`/`comment` get the same non-string-input hardening. Low real-world exploitability (CrowdSec's own plugin always sends strings, and the listen address defaults to `127.0.0.1`), but a malformed/malicious POST shouldn't have been able to reach this far in the first place.
- **`ABUSEIPDB_QUOTA_RESERVE_RECHECK_DELAY` set to 0 or a negative value would have caused an unbounded tight loop.** Unlike a retry (bounded by `MAX_RETRIES`, so a too-short `RETRY_DELAY` just means a few fast attempts before giving up), a quota re-check reschedules itself for as long as quota stays reserved — which can be indefinite (e.g. a `HIGH`/`MEDIUM` reserve set above the actual daily limit). A non-positive delay would have meant near-instant timer refires hammering the lock and the database for as long as that condition held. Now clamped to the safe default (300) with a startup warning if an invalid value is given.
- **`ABUSEIPDB_BACKUP_RETENTION` set to a negative value crashed every `--backup` run (and the backup timer) with `IndexError: pop from empty list`.** `run_backup()`'s pruning loop (`while len(existing) > BACKUP_RETENTION: existing.pop(0)`) stays true even once the backup directory is already empty when the configured retention is negative (`0 > -1` is `True`), so the very next `pop(0)` had nothing left to pop. Fixed at two layers: the module-level value now floors to 0 (with a startup warning) like the quota fix above, and `run_backup()` itself floors defensively too, so this can't crash regardless of how the value ends up set by the time it runs.

### Added
- 7 new tests: a real 20-thread concurrency test confirming the sweep-lock change doesn't let concurrent callers double-claim a sweep; a live-server regression test confirming a numeric `"ip"` field is rejected rather than coerced; and negative-value regression tests for both `ABUSEIPDB_QUOTA_RESERVE_RECHECK_DELAY` and `ABUSEIPDB_BACKUP_RETENTION` (the latter confirmed first to actually crash pre-fix, not just asserted post-fix). Full suite (384 tests) re-run 10x in a row with no flakiness, consistent with the project's existing practice for lock-sensitive changes.

## [3.0.3] - External review + one internal audit pass, all findings independently verified

An external AI review flagged 13 points, 4 marked as likely real bugs. None were taken at face value — each was checked directly against the current code before anything was changed. All four held up (one, #3 below, turned out narrower than described). A subsequent full read-through audit of the entire file (not just the changed areas) turned up two more issues on top of that, both restart-path gaps related to the fixes below. No breaking changes.

### Fixed — from the external review
- **A report held back by quota reservation (`ABUSEIPDB_QUOTA_RESERVE_MEDIUM`/`_HIGH`) was silently dropped for good**, not just delayed. `quota_reserved_for()` returning `True` led straight to a bare `_sqlite_delete_pending(ip); return` in all three places a report can be reserved (`process_alert()`'s "no entry" branch, its escalation branch, and `_finalize_pending()`) — the report itself never got sent, retried, or re-queued once the moment passed. Now reschedules itself via `_schedule_pending()` at a new `ABUSEIPDB_QUOTA_RESERVE_RECHECK_DELAY` (default 300s) instead, so it's re-checked once quota pressure eases rather than vanishing. The "no entry" branch's existing unconditional-cancel-of-any-pending-timer logic also had to change: since a quota re-check now creates a `pending_timers` entry with no corresponding `reports` row, a newly-arriving *lower*-severity alert for the same IP could otherwise evict an already-waiting higher-severity re-check. Given the same severity-comparison guard the escalation branch already used.
- **The persisted retry-attempt counter was off by one, causing a proxy restart to silently repeat an already-failed attempt.** `send_with_retry()` persisted `attempt` (the number that had just failed) into `retry_queue`, but the in-memory `threading.Timer` for the *next* try was already scheduled with `attempt + 1`. `resume_state_from_cache()` reads that persisted value directly as the next attempt to make on restart — so restarting mid-backoff replayed the same attempt number instead of advancing, silently extending `MAX_RETRIES` by one every time a restart happened to land during a retry window. Now persists `attempt + 1`, matching what the live timer was already using.
- **Giving up on a report after exhausting all retries left it permanently marked as "reported" in the `reports` dedup table**, even though it was never actually delivered — silently suppressing every future alert for that IP indefinitely (worse than described: this also defeats `--reconcile`, which only looks for IPs *missing* from `reports`, so it could never catch or retry these either). `send_with_retry()` cleared `retry_queue` on giving up but never touched the optimistically-written `reports` entry. Fixed by threading a `report_time` parameter through every call site (the three `process_alert()`/`_finalize_pending()` starting points, plus the internal retry `threading.Timer` call) and deleting the `reports` row on final give-up — but only when its `time` still matches `report_time`, so a fresher entry written by a newer escalation that came in while the old chain was still retrying isn't accidentally wiped out.
- **Two concurrent retry chains for the same IP could collide while persisting to `retry_queue`**, since it's keyed by IP alone with no per-chain identity. Narrower than the original report suggested — each `threading.Timer` closure already sends its own correctly-captured data, so a stale report body was never actually the risk — but a genuine race did exist in the SQLite writes when, e.g., an original report was still mid-retry and a new escalation for the same IP started a second, independent `send_with_retry()` thread. New `_cancel_active_retry_chain(ip)` cancels any active timer and clears its persisted row before a new chain starts, at all three `send_with_retry()`-launching call sites — same precedent as the pending-timer cancellation already used for escalations, extended to retries. The newer chain always wins; the older one's next scheduled attempt simply never fires.

### Fixed — from internal audit
- **A retry or delayed escalation triggered by `--reconcile` was silently lost if it needed a second attempt.** `--reconcile` runs as its own short-lived CLI process; a report it starts that fails gets a `threading.Timer` scheduled for the retry exactly like a live alert would, but that timer exists only in the CLI process's memory — gone the instant the process exits right after `run_reconcile()` returns, even though the persisted `retry_queue`/`pending` row it wrote survives on disk. The row would then just sit there, invisible to the long-running proxy service (whose own `retry_timers`/`pending_timers` are separate, in-memory, per-process state), until either an unrelated future alert for that IP happened to touch it or the service itself was restarted. Fixed with a new periodic check in the long-running service (`ABUSEIPDB_ORPHAN_RESCAN_INTERVAL`, default 60s): it re-arms any persisted pending/retry row with no matching in-memory timer in that process, regardless of which process originally wrote it. This is the same re-arming logic `resume_state_from_cache()` already runs once at startup — now factored into shared `_arm_pending_timer()`/`_arm_retry_timer()` helpers used by both, so there's exactly one place that knows how to correctly turn a persisted row back into a live timer (report_time included) instead of two copies that can silently drift apart, which is exactly how the `resume_state_from_cache()` gap below happened in the first place.
- **`resume_state_from_cache()` had the exact same "permanently marked as reported" bug as the fix above it, just via the restart path instead of the live one.** It re-arms outstanding retries from `retry_queue` on every proxy restart, but wasn't passing `report_time` to `send_with_retry()` at all — a retry chain that survived a restart and then exhausted its retries fell right back into the give-up bug. Found and fixed by looking up the matching `reports` row's timestamp when resuming, the same value that chain was started with originally, and folded into the `_arm_retry_timer()` factoring above.

### Added
- New env vars `ABUSEIPDB_QUOTA_RESERVE_RECHECK_DELAY` (default `300`) and `ABUSEIPDB_ORPHAN_RESCAN_INTERVAL` (default `60`), documented in both `.env.example` files and both READMEs (EN/DE), including an update to the `--reconcile` section explaining how the orphan-rescan closes its retry gap.
- 20 new tests: retry-counter persistence across a simulated restart; give-up correctly clearing (and correctly *not* clearing a fresher) `reports` entry, including specifically through the restart/resume path; quota-reserve deferral actually re-sending once quota frees up, and its interaction with the "no entry" pending-timer priority guard; the retry-chain-cancellation race, covered both as a fast simulated-timer integration test and as a real multi-threaded stress test against the actual `ThreadingHTTPServer` with real (short-delay) retry timers; and the orphan-rescan mechanism, including a full two-process simulation (`--reconcile` writes a row and "exits", a separate long-running instance sharing the same cache file reaps and correctly completes it, report_time recovery included). Full suite (377 tests) re-run 10x in a row with no flakiness, consistent with the project's existing practice for lock-sensitive changes.

## [3.0.2] - Hot-path rewritten to single-row cache operations

No breaking changes, but a real behavioral change worth knowing about (see below). Follow-up to the "investigated, not changed" note in 3.0.1.

### Changed
- **`process_alert()`, `_schedule_pending()`, `_finalize_pending()`, and `send_with_retry()` no longer read or write the entire cache on every alert.** They used to call `load_cache()`/`save_cache()` — a full read (or DELETE-all-then-reinsert-all write) of every row in every table — for every single incoming alert, meaning the true cost of processing "one new report" scaled with the *total* number of tracked IPs, not with the one alert actually being handled. New single-row operations (`_sqlite_get_report()`, `_sqlite_upsert_report()`, and equivalents for `pending`/`retry_queue`) touch only the one row a given alert actually needs. Measured directly: 11.5ms → 2.3ms per alert against a 5,000-entry cache (~5x), and — the more important number — 1.8ms per alert against a 50,000-entry cache, essentially unchanged from the 5,000-entry case. The old approach scaled linearly with cache size; this doesn't scale with it at all. `load_cache()`/`save_cache()` themselves are unchanged and still used exactly as before everywhere else (`--backup`, `--reconcile`, `--vacuum`, `--import`/`--export`, `--migrate-to-sqlite`, startup resume) — none of those run on the request hot path, so there was nothing to gain by touching them.
- **Behavioral change**: reports older than 24h used to be pruned from the database as an inline side effect of *every* alert (whichever alert happened to trigger the read-modify-write of the whole table). That's gone — an individual alert's dedup decision only ever depended on its own row, never on whether unrelated stale rows had been cleaned up, so nothing about correctness required doing this eagerly. In its place: a new `_maybe_sweep_stale_reports()` runs a single lightweight `DELETE FROM reports WHERE time <= ?` (not a Python-side read of every row) at most once an hour, keeping the table from growing unboundedly between `--vacuum` runs for anyone who hasn't set up the vacuum timer, without paying that cost on literally every alert.

### Added
- 12 new tests: `test_cache_sqlite.py` covers the new single-row operations and the periodic sweep directly (including that it only runs once per hour, not every call); `test_dedup_escalation.py` adds a regression test confirming a stale row for a *different* IP is left alone by an unrelated alert (the specific behavior that would have silently broken if the rewrite had gotten the row-scoping wrong). Full suite re-run 15x in a row against the concurrency/dedup/retry/cache tests specifically (this touches the same locking as the `ThreadingHTTPServer` work) with no flakiness.

## [3.0.1] - Full audit pass: bugs, logic errors, performance

A deliberate full read-through of the entire codebase (not tied to a specific feature), looking for real bugs and performance issues rather than adding anything new. No breaking changes.

### Fixed
- **`install.sh` was overwriting the entire env file down to just the API key on every run.** Writing the key used a plain `cat > "${ENV_PATH}"`, which replaced the whole file instead of updating just that one line — every other setting (`ABUSEIPDB_CROWDSEC_BOUNCER_KEY`, `ABUSEIPDB_ALLOWED_SOURCE_IPS`, notification tokens, custom cache paths, anything) was silently destroyed. Since `update.sh` re-runs `install.sh` on every applied update, this meant **every update wiped all customization beyond the API key**. Also explains why the reconcile-timer offer (which reads `ABUSEIPDB_CROWDSEC_BOUNCER_KEY` from the same file, later in the script) could never actually find it on a re-run — the file had already been emptied by the time it checked. Fixed to preserve every other line, verified against a fresh file, an existing file with other settings, an empty file, and a file containing only the old API-key line (each a distinct edge case under `set -euo pipefail`).
- **Matrix notifications could silently collide and get dropped**: the transaction ID was a plain millisecond timestamp — two `notify()` calls landing in the same millisecond (plausible, since each backend fires in its own thread) would produce the same `txn_id`, and Matrix treats a repeated `txn_id` as a retry of the same request rather than sending it as a new message. Switched to a UUID (no collision risk regardless of timing).
- **`_whitelist_cache` grew without bound**: every IP ever checked (with `ABUSEIPDB_SKIP_WHITELISTED=true`) stayed in memory for the life of the process, even long after its TTL expired — a slow leak on any long-running instance with a lot of distinct source IPs (the honeypot-style setups the README already calls out for this setting being exactly the realistic case). Now sweeps expired entries opportunistically on every write, bounding it to roughly "unique IPs checked in the last TTL window."
- **A malformed `Content-Length` header crashed unhandled** instead of getting the same clean `500` response a malformed request body already got — the `int(...)` parse ran outside the `try`/`except` that covered everything else in the handler. Moved inside it.
- **`/health` loaded the entire report cache just to take `len()` of it** — on a large cache (the 24h retention window this proxy uses for escalation purposes can genuinely reach thousands of entries on a high-traffic/honeypot-style deployment) this meant materializing every tracked report into Python objects on every poll, just to discard all of it but a count. New `count_tracked_reports()` does a single `SELECT COUNT(*)` instead — measured ~9x faster against a 3,000-entry cache in this pass's own benchmark.
- **`run_reconcile()`'s "already known" tracking was a static snapshot** taken once before the loop — if `fetch_crowdsec_active_decisions()` ever returned the same IP twice (overlapping decisions from different scenarios), it would get double-counted in the summary and notification, even though `process_alert()`'s own dedup already meant it was never actually double-*reported*. Now updates the tracking set as it goes.
- Several stale comments/docs left over from earlier changes: a comment fragment cut off mid-sentence from the 3.0.0 edit, a "single-threaded" claim in the README/Dockerfile/docker-compose.yml comments left over from before the v2.8.0 `ThreadingHTTPServer` switch, a `--vacuum` docstring reference to an "UPSERT/DELETE" approach from a change that got reverted before landing (see below), a stale `python:3.12-alpine` mention in `Docker/Dockerfile`'s own comment (the `FROM` line itself had already moved to 3.13 via Dependabot).

### Investigated, not changed
- **`save_cache()`'s full delete-and-reinsert-every-row approach was benchmarked against an UPSERT-based rewrite** (motivated by every single incoming alert calling `save_cache()` with the *entire* in-memory cache, an O(n) operation per alert). The UPSERT version turned out to *not* be a clear win in practice — SQLite's `DELETE FROM table` with no `WHERE` clause is already very cheap (an internal truncate-style optimization), and `executemany()` still has to iterate every row in the cache dict either way, so the fundamental O(n)-per-alert cost doesn't go away without changing which data gets passed to `save_cache()` in the first place. A real fix means restructuring the hot path (`process_alert()`, `_finalize_pending()`, `send_with_retry()`) to read/write only the one row that actually changed instead of round-tripping the whole cache — a much larger, higher-risk change to the core reporting path than this pass's scope. Documented here rather than pushed through hastily; a candidate for a dedicated future pass if it ever proves to matter in practice (the 24h retention keeps the table bounded, and `--vacuum` prunes it — for most realistic deployments this is unlikely to bite).

## [3.0.0] - JSON cache backend removed

**Breaking change**, flagged since the deprecation in v2.9.0. SQLite is now the only cache backend.

### Removed
- **`ABUSEIPDB_CACHE_BACKEND=json`**: the backend itself, and `_load_cache_json()`/`_save_cache_json()`, are gone entirely. `load_cache()`/`save_cache()` always use SQLite now, with no branching. Setting `ABUSEIPDB_CACHE_BACKEND` to anything other than `sqlite` (a leftover env file from before 3.0.0 is the realistic case) no longer breaks startup — it logs a loud one-time warning (at both module-import time and in `--check-config`) and continues on SQLite, so an old config degrades gracefully instead of failing outright or, worse, silently doing the wrong thing.
- Safety net for the same upgrade scenario: if `ABUSEIPDB_CACHE_FILE` ends in `.json` (pointing at an old JSON cache path), it's automatically redirected to a sibling `.db` path instead — a JSON-formatted file must never be opened as a SQLite database, which is what would otherwise happen the moment anything tried to write to it. Also warns loudly, with the exact `--migrate-to-sqlite` command to run.

### Changed
- **`--migrate-to-sqlite`**: redesigned around an explicit source argument — `--migrate-to-sqlite SOURCE_JSON_FILE [--migrate-target PATH]` — instead of reading `ABUSEIPDB_CACHE_BACKEND`/`ABUSEIPDB_CACHE_FILE` (there's nothing for those to point at as a JSON cache anymore). Still doesn't modify or delete the source file, still refuses to overwrite an existing target, still understands the flat v1.0.0 format.
- The **automatic legacy-cache.json import** (`_migrate_json_to_sqlite_if_needed()`, introduced in v2.0.0) is unchanged and stays — this is the smooth zero-action upgrade path for anyone whose `cache.json` sits at the default location right next to where `cache.db` gets created; only the *explicit* `--migrate-to-sqlite` CLI flag needed a signature change.
- `--vacuum` and `--check-config`'s cache section no longer have JSON-vs-SQLite conditionals — they just always apply, since there's only one backend to apply to.

### Fixed (carried over from the v2.9.0 CI investigation, included here for completeness)
- `tests/conftest.py`'s `make_proxy` fixture had `ABUSEIPDB_CACHE_BACKEND=json` as its *default* for nearly the entire test suite — a latent inconsistency between what most tests actually exercised and what the module defaults to (SQLite, since v2.0.0). Flipped to SQLite. Every test file that assumed a JSON cache file was reviewed and updated: `test_cache.py` (removed two now-nonexistent legacy-format-upgrade-via-`load_cache()` tests — that capability lives in `--migrate-to-sqlite` and is tested there), `test_vacuum.py` (removed three JSON-backend no-op tests), `test_check_config.py`, `test_export_import.py`, `test_cache_sqlite.py`, and `tests/test_migrate_to_sqlite.py` (fully rewritten for the new signature).

## [2.9.0] - JSON backend deprecation + migration path, concurrent-request ceiling, IPv6 audit, live self-test

Purely additive/fixes — no breaking changes yet (3.0.0 will remove the JSON backend entirely).

### Deprecated
- **`ABUSEIPDB_CACHE_BACKEND=json`** — will be removed entirely in 3.0.0. Logs a warning on startup and in `--check-config`. Migration path: new **`--migrate-to-sqlite [PATH]`** CLI flag writes the current JSON cache into a new SQLite database (default target: same filename with a `.db` extension) without touching or deleting the JSON file, and refuses to overwrite an existing target. Understands both the current cache format and the flat v1.0.0 one. `tests/test_migrate_to_sqlite.py`: 11 tests.

### Added
- **`ABUSEIPDB_MAX_CONCURRENT_REQUESTS`** (default `50`, `0` disables): a safety net, not a normal throttle, against an unbounded number of request-handling threads under `ThreadingHTTPServer` (v2.8.0) — a misconfiguration or bug feeding the proxy a flood of decisions could otherwise spin up threads without limit. A non-blocking semaphore around the whole request handler; over the limit gets an immediate `503` + `Retry-After: 1` rather than queuing. New `abuseipdb_proxy_reports_rejected_overload_total` metric.
- **RFC 5737 / RFC 3849 documentation ranges** (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) added to the default ignore list alongside the existing private/reserved ranges — these are reserved exclusively for documentation and examples, never assigned to a real host, so never a genuine attacker. Controlled by the same `ABUSEIPDB_IGNORE_PRIVATE` toggle. This also underpins the new live self-test below: 192.0.2.1 is guaranteed to always be filtered, so that self-test can never actually reach the real AbuseIPDB API.
- **`--doctor` live self-test**: beyond `--doctor`'s existing static checks (which only validate the current CLI invocation's own environment), it now sends one synthetic test alert through the *actually running* proxy's real HTTP endpoint on localhost — confirming the deployed instance is truly listening and processing requests correctly, not just that the configuration looks right on paper. Skipped by `--no-network`, same as the existing api.abuseipdb.com reachability check.
- **IPv6 audit**: dedicated test coverage (`tests/test_ipv6.py`, 10 tests) for the source-IP allowlist, custom ignore-list entries, CrowdSec decision reconciliation, and a full end-to-end round-trip through the real running server — all with IPv6 addresses specifically. No bugs found (the existing `ipaddress`-module-based code already handled IPv6 correctly throughout), but it wasn't previously exercised this thoroughly.
- `tests/test_threading_server.py`: 2 new tests for the concurrent-request ceiling (rejects over the limit with 503; `0` disables it) — 6 total in that file now. `tests/test_doctor.py`: 6 new tests for the live self-test, including a full end-to-end run against a real server — 26 total in that file now.
- A shared `running_server` fixture (starts a real `ThreadingHTTPServer` on an OS-assigned port) moved from `test_threading_server.py` into `conftest.py` so `test_ipv6.py` and `test_doctor.py` could reuse it too, instead of duplicating it.

### Fixed
- `tests/test_ip_filtering.py` used `203.0.113.5` (TEST-NET-3) as an example of a "public, never ignored" IP — now correctly moved to the "always ignored" test cases, since it's a documentation range as of this release. A couple of other tests using TEST-NET-3 addresses as arbitrary stand-ins for "some public IP" were updated to non-reserved addresses so they keep testing what they were meant to.

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
