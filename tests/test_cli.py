"""
End-to-end CLI tests, run as real subprocesses against the actual
script (not the imported module), covering what a user actually types.
No network access needed: --version and --notify-with-no-backend both
exit before anything would try to reach the network.
"""
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "abuseipdb_proxy.py"


def run(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=10, env=env,
    )


def test_version_flag_prints_version_and_exits_zero(proxy):
    result = run("--version")
    assert result.returncode == 0
    assert proxy.VERSION in result.stdout


def test_missing_api_key_without_dry_run_exits_nonzero(monkeypatch):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    result = run(env=env)
    assert result.returncode == 1
    assert "ABUSEIPDB_API_KEY" in result.stderr


def test_test_notify_without_backend_configured_exits_nonzero():
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    result = run("--test-notify", env=env)
    assert result.returncode == 1
    assert "No notification backend configured" in result.stderr


def test_notify_without_message_argument_is_a_usage_error():
    result = run("--notify")
    assert result.returncode == 2  # argparse's standard exit code for bad usage


def test_notify_priority_rejects_invalid_choice():
    result = run("--notify", "hi", "--notify-priority", "urgent")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr
