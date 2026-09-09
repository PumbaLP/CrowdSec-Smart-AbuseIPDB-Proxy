"""Only used for subprocess coverage measurement during `pytest --cov`.

Many of this project's tests exercise the CLI by spawning a real
`python3 abuseipdb_proxy.py --flag` subprocess (test_cli.py,
test_check_config.py, test_doctor.py, test_backup.py, ...) rather than
calling functions directly -- the only way to genuinely test argument
parsing and the __main__ dispatch logic. coverage.py can't see inside a
separate process by default, though, so without this file that
subprocess-only code (parse_args(), the CLI dispatch block) shows up as
"uncovered" even though it's exercised on every test run.

Python's `site` module auto-imports a module named `sitecustomize` if one
is found anywhere on sys.path at interpreter startup -- and a script's
own directory is always sys.path[0], so this file being right next to
abuseipdb_proxy.py is what makes it get picked up automatically for
every subprocess test spawns, no PYTHONPATH configuration needed.

A complete no-op otherwise: it only does anything when
COVERAGE_PROCESS_START is set in the environment (conftest.py sets it,
but only when the outer test run itself is under `pytest --cov`), so a
plain `pytest` invocation -- or running abuseipdb_proxy.py directly,
outside of tests entirely -- is entirely unaffected.
"""
import os

if os.environ.get("COVERAGE_PROCESS_START"):
    import coverage
    coverage.process_startup()
