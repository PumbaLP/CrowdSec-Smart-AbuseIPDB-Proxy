# Contributing

Thanks for considering a contribution — issues and PRs are welcome.

## Reporting a bug

Please include:

- What you expected to happen vs. what actually happened
- The relevant log output: `journalctl -u abuseipdb-proxy.service -n 100`
- Your `ABUSEIPDB_REPORT_WINDOW` and `ABUSEIPDB_CACHE_FILE` values if you changed them from the defaults
- CrowdSec version (`cscli version`) and OS/distro

Please **redact your API key** and any real IP addresses you don't want public before pasting logs.

**Found a security issue instead?** Don't open a public issue for it — see [`SECURITY.md`](SECURITY.md) for how to report it privately.

## Testing locally

The proxy has no external dependencies beyond the Python standard library, so you can run it directly without installing anything.

**Option A — dry-run mode (no API key needed, nothing is actually sent):**

```bash
export ABUSEIPDB_CACHE_FILE=/tmp/abuseipdb-proxy-test-cache.json
python3 abuseipdb_proxy.py --dry-run
```

Reports are logged to stderr instead of being sent to AbuseIPDB — handy for testing new CrowdSec scenarios or the escalation/dedup logic without burning API quota.

**Option B — real API calls:**

```bash
export ABUSEIPDB_API_KEY=your_key_here
export ABUSEIPDB_CACHE_FILE=/tmp/abuseipdb-proxy-test-cache.json
python3 abuseipdb_proxy.py
```

Either way, send it a test alert manually:

```bash
curl -X POST http://127.0.0.1:9999/ \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.10", "categories": "18,22", "comment": "test report"}'
```

Check `/tmp/abuseipdb-proxy-test-cache.json` to confirm the entry was recorded.

To test the full pipeline including CrowdSec's templating, point the `url` in `abuseipdb.yaml` at your local test instance and trigger a real scenario (or `cscli alerts add` a synthetic one).

**Option C — the automated test suite:**

```bash
pip install -r tests/requirements.txt
pytest
```

Covers the dedup/escalation decision logic, retry/backoff, cache persistence for both backends (JSON and SQLite, including legacy-format upgrades), IP filtering, all notification backends, and the CLI — no network access or real AbuseIPDB key needed. If you're adding a new scenario/category mapping or touching `process_alert`/`send_with_retry`/`load_cache`/`save_cache`, add a test alongside it rather than a throwaway script; the ad-hoc scripts used during earlier development never made it into the repo, which this suite exists to fix. If you touch the cache layer, make sure both `test_cache.py` (JSON) and `test_cache_sqlite.py` (SQLite) still pass — `load_cache()`/`save_cache()` must keep behaving identically from the caller's perspective regardless of backend.

**Testing a severity/window/quota-reserve config change specifically:** `--simulate CATEGORIES [--simulate-comment TEXT]` previews how a categories string would be handled — derived severity, which report window applies and why, whether it'd be held back by quota reservation — without sending anything or spinning up the HTTP server at all. Faster than Option A/B's curl round-trip when you're only trying to answer "given my config, what would happen to this category combination":

```bash
python3 abuseipdb_proxy.py --simulate "15,18" --simulate-comment "test comment"
```

## Before opening a PR

- Run `shellcheck install.sh update.sh uninstall.sh`, `python3 -m py_compile abuseipdb_proxy.py`, and `pytest` locally — the CI workflow runs the same checks
- If you touched `install.sh` or `update.sh`: `sudo bash tests/test_shell_scripts.sh` — behavioral regression tests (a throwaway git remote/checkout, real non-interactive invocations) for two real bugs neither ShellCheck nor the Python suite could catch, since both were about runtime behavior rather than syntax (see CHANGELOG 3.1.1). Destructive (writes to `/etc`, `/usr/local/bin`, `/var/lib`, `/etc/systemd/system`, though it cleans up after itself) — run it in a VM/container, not on a real proxy host. Deliberately not pytest-discoverable (it's a `.sh` file, so it sits in `tests/` alongside the Python suite without `pytest` trying to collect it) and not part of the normal `pytest` run for that same reason. CI runs this on every push as its own `shell-scripts` job.
- If you touched any `.service`/`.timer` file: `systemd-analyze verify <file>` — CI runs this on all of them (`|| true`'d there since the referenced `ExecStart` binary won't exist in CI's checkout either; a syntax problem in the unit file itself still fails the line's own output, just not the job). Catches things like a typo'd `Type=` value locally before pushing.
- If you touched anything in `Docker/` and have Docker available locally: `docker build -f Docker/Dockerfile -t abuseipdb-proxy:dev .` (context is the repo root, not `Docker/`, since the Dockerfile needs `abuseipdb_proxy.py` from there) and a quick `docker run --rm abuseipdb-proxy:dev --version`. CI builds and smoke-tests the image on every push either way (including a check that `sqlite3` actually works inside it), so this isn't strictly required, just faster feedback.
- Keep changes focused; unrelated formatting changes make review harder
- Update the README (both `README.md` and `README.de.md`) if you change behavior, config variables, CLI flags, or installation steps
- **Adding or renaming an env var?** Update both `abuseipdb-proxy.env.example` and `Docker/docker-compose.env.example` — they document the same variables for two different deployment paths (systemd vs. Docker) and are expected to stay in sync. Easy to update one and forget the other; nothing currently catches that automatically, so it's on review to check.
- Adding or bumping a GitHub Action in `.github/workflows/`? Pin it to a full 40-character commit SHA with a `# vX.Y.Z` comment (not a mutable tag like `@v4`) — see the existing `uses:` lines for the format. `git ls-remote --tags https://github.com/<owner>/<repo> <tag> "<tag>^{}"` resolves a tag to its commit SHA (use the `^{}` line if both appear — that means it's an annotated tag, and the unadorned line is a tag object, not a commit). [`Dependabot`](.github/dependabot.yml) keeps existing pins current automatically; this only matters when adding something new by hand.

## Releasing a new version

1. Add a new `## [X.Y.Z] - Short human-readable subtitle` section at the top of `CHANGELOG.md`, above the previous version. The subtitle after the ` - ` becomes the GitHub Release title, and everything below it (until the next `## [` header) becomes the release notes — so write it the way you'd want it to read on the Releases page, not like a raw commit log.
2. Bump `VERSION` in `abuseipdb_proxy.py` to match.
3. Commit and push.
4. Tag and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
5. `release.yml` picks up the tag and creates the GitHub Release automatically (title/body from the CHANGELOG section above), attaching `Docker/docker-compose.yml` and `Docker/docker-compose.env.example` as downloadable assets so someone can grab just those two files without cloning the repo. Publishing that Release in turn triggers `docker-publish.yml`, which builds and pushes multi-arch (amd64/arm64) images to GHCR tagged `X.Y.Z`, `X.Y`, `X`, `latest`, and `sha-<commit>` — signed (keyless, cosign/Sigstore) with an SBOM generated and attached to the same Release. No manual copy-pasting, `docker push`, or `docker login` needed for any of it.
6. **First release only**: the first image `docker-publish.yml` ever pushes to a new GHCR package defaults to private. Go to the package's settings on GitHub (org/user → Packages → this package → Package settings) and set visibility to Public, otherwise `docker compose pull` fails for everyone else with a 403. Every release after that stays public automatically.

## Ideas that would be especially welcome

- Signal support — only really practical via a self-hosted bridge like [signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api); worth adding if someone's already running that bridge, not worth requiring otherwise
- A periodic (or `/health`-driven) reconciliation between `retry_queue`/`pending` and CrowdSec's own active-decision list, catching the inverse case `--reconcile` already covers (a report that's been retrying/pending for a long time for an IP CrowdSec has since un-decided about) — low priority, since `_check_retry_backlog`'s sustained-backlog warning already surfaces the "AbuseIPDB itself seems to be down" case this would mostly overlap with

**Deliberately not planned:** an attack-map/GeoIP visualization was explored early on and dropped — CrowdSec's own console already does this better, and this project's actual value is being a much more capable interface to AbuseIPDB specifically than CrowdSec's own AbuseIPDB integration offers, not a second dashboard. A PR adding one back would likely be declined for that reason, not because it wouldn't work.
