"""run_doctor()/format_doctor_output() and the --doctor/--no-network CLI flags."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "abuseipdb_proxy.py"


def run(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=15, env=env,
    )


def test_includes_everything_check_config_covers(proxy):
    config_messages = {msg for _, msg in proxy.check_config()}
    doctor_messages = {msg for _, msg in proxy.run_doctor(check_network=False)}
    assert config_messages <= doctor_messages


def test_network_check_skipped_when_disabled(proxy):
    results = proxy.run_doctor(check_network=False)
    assert any(level == "skip" and "Network" in msg for level, msg in results)


def test_systemctl_missing_reports_skip_not_fail(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "_run_systemctl", lambda *a: (None, None))
    results = proxy.run_doctor(check_network=False)
    assert any(level == "skip" and "systemd" in msg for level, msg in results)
    assert not any(level == "fail" for level, _ in results)


def test_systemctl_reports_active_service_as_ok(proxy, monkeypatch):
    def fake_systemctl(*args):
        if "is-active" in args:
            return 0, "active"
        return 0, "enabled"
    monkeypatch.setattr(proxy, "_run_systemctl", fake_systemctl)
    results = proxy.run_doctor(check_network=False)
    assert any(level == "ok" and "is active" in msg for level, msg in results)
    assert any(level == "ok" and "is enabled" in msg for level, msg in results)


def test_systemctl_reports_inactive_service_as_warn(proxy, monkeypatch):
    def fake_systemctl(*args):
        if "is-active" in args:
            return 3, "inactive"
        return 1, "disabled"
    monkeypatch.setattr(proxy, "_run_systemctl", fake_systemctl)
    results = proxy.run_doctor(check_network=False)
    assert any(level == "warn" and "not active" in msg for level, msg in results)
    assert any(level == "warn" and "not enabled" in msg for level, msg in results)


def test_missing_env_file_skips_permission_check(proxy, monkeypatch):
    real_exists = os.path.exists
    monkeypatch.setattr(
        proxy.os.path, "exists",
        lambda p: False if "abuseipdb-proxy.env" in p else real_exists(p),
    )
    results = proxy.run_doctor(check_network=False)
    assert any(level == "skip" and "abuseipdb-proxy.env" in msg for level, msg in results)


def test_overly_permissive_env_file_warns(proxy, monkeypatch, tmp_path):
    fake_env = tmp_path / "abuseipdb-proxy.env"
    fake_env.write_text("ABUSEIPDB_API_KEY=x")
    fake_env.chmod(0o644)
    monkeypatch.setattr(proxy, "_run_systemctl", lambda *a: (None, None))

    real_exists = os.path.exists

    def fake_exists(p):
        if p == "/etc/abuseipdb-proxy/abuseipdb-proxy.env":
            return True
        return real_exists(p)

    real_stat = os.stat

    def fake_stat(p, *a, **kw):
        if p == "/etc/abuseipdb-proxy/abuseipdb-proxy.env":
            return real_stat(fake_env)
        return real_stat(p, *a, **kw)

    monkeypatch.setattr(proxy.os.path, "exists", fake_exists)
    monkeypatch.setattr(proxy.os, "stat", fake_stat)

    results = proxy.run_doctor(check_network=False)
    assert any(level == "warn" and "more permissive than 600" in msg for level, msg in results)


def test_missing_crowdsec_files_skip_cleanly(proxy):
    # Sandbox/test environment never has real /etc/crowdsec/... — this is
    # really just confirming the normal path (no monkeypatching) doesn't
    # explode and reports skip, not fail.
    results = proxy.run_doctor(check_network=False)
    assert any(level == "skip" and "abuseipdb.yaml" in msg for level, msg in results)
    assert not any(level == "fail" for level, _ in results)


def test_profiles_yaml_missing_abuseipdb_default_warns(proxy, monkeypatch, tmp_path):
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text("name: default\nfilters:\n  - Alert.Remediation == true\n")

    real_exists = os.path.exists

    def fake_exists(p):
        if p == "/etc/crowdsec/profiles.yaml":
            return True
        return real_exists(p)

    real_open = open

    def fake_open(p, *a, **kw):
        if p == "/etc/crowdsec/profiles.yaml":
            return real_open(profiles, *a, **kw)
        return real_open(p, *a, **kw)

    monkeypatch.setattr(proxy.os.path, "exists", fake_exists)
    monkeypatch.setattr("builtins.open", fake_open)

    results = proxy.run_doctor(check_network=False)
    assert any(level == "warn" and "NOT referenced" in msg for level, msg in results)


def test_profiles_yaml_with_abuseipdb_default_is_ok(proxy, monkeypatch, tmp_path):
    profiles = tmp_path / "profiles.yaml"
    profiles.write_text("name: default\nnotifications:\n  - abuseipdb_default\n")

    real_exists = os.path.exists

    def fake_exists(p):
        if p == "/etc/crowdsec/profiles.yaml":
            return True
        return real_exists(p)

    real_open = open

    def fake_open(p, *a, **kw):
        if p == "/etc/crowdsec/profiles.yaml":
            return real_open(profiles, *a, **kw)
        return real_open(p, *a, **kw)

    monkeypatch.setattr(proxy.os.path, "exists", fake_exists)
    monkeypatch.setattr("builtins.open", fake_open)

    results = proxy.run_doctor(check_network=False)
    assert any(level == "ok" and "is referenced" in msg for level, msg in results)


def test_broken_cache_reports_fail(proxy, monkeypatch):
    def boom():
        raise RuntimeError("disk exploded")
    monkeypatch.setattr(proxy, "load_cache", boom)
    results = proxy.run_doctor(check_network=False)
    assert any(level == "fail" and "disk exploded" in msg for level, msg in results)


def test_healthy_cache_reports_ok_with_count(proxy):
    proxy.save_cache({"reports": {"1.1.1.1": {"time": 1, "severity": 1},
                                   "2.2.2.2": {"time": 1, "severity": 1}},
                       "pending": {}, "retry_queue": {}})
    results = proxy.run_doctor(check_network=False)
    assert any(level == "ok" and "2 report(s)" in msg for level, msg in results)


def test_network_check_reaches_a_real_response(proxy, monkeypatch):
    # Doesn't hit the real network — verifies the try/except branches
    # actually run with a fake urlopen instead.
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    monkeypatch.setattr(proxy.urllib.request, "urlopen", lambda req, timeout=5: FakeResponse())
    results = proxy.run_doctor(check_network=True)
    assert any(level == "ok" and "reachable" in msg for level, msg in results)


def test_network_check_http_error_still_counts_as_reachable(proxy, monkeypatch):
    def raise_http_error(req, timeout=5):
        raise proxy.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
    monkeypatch.setattr(proxy.urllib.request, "urlopen", raise_http_error)
    results = proxy.run_doctor(check_network=True)
    assert any(level == "ok" and "reachable" in msg for level, msg in results)


def test_network_check_connection_error_warns(proxy, monkeypatch):
    def raise_it(req, timeout=5):
        raise OSError("network unreachable")
    monkeypatch.setattr(proxy.urllib.request, "urlopen", raise_it)
    results = proxy.run_doctor(check_network=True)
    assert any(level == "warn" and "not reachable" in msg for level, msg in results)


# --- format_doctor_output() --------------------------------------------------

def test_format_shows_skip_symbol(proxy):
    text = proxy.format_doctor_output([("skip", "n/a here")])
    assert "[SKIP]" in text


def test_format_counts_only_fail_and_warn_not_skip(proxy):
    text = proxy.format_doctor_output([("skip", "a"), ("ok", "b"), ("warn", "c")])
    assert "No problems, 1 warning(s) to review." in text


# --- CLI wiring --------------------------------------------------------------

def _base_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    env.update(extra)
    return env


def test_cli_doctor_with_no_network_exits_zero_when_healthy(tmp_path):
    result = run("--doctor", "--no-network", env=_base_env(tmp_path))
    assert result.returncode == 0
    assert "[FAIL]" not in result.stdout


def test_cli_doctor_json_output(tmp_path):
    import json as jsonlib
    result = run("--doctor", "--no-network", "--json", env=_base_env(tmp_path))
    data = jsonlib.loads(result.stdout)
    assert isinstance(data, list)
    assert any(item["level"] == "skip" for item in data)


def test_cli_doctor_exits_one_on_failure(tmp_path):
    env = _base_env(tmp_path)
    del env["ABUSEIPDB_DRY_RUN"]
    result = run("--doctor", "--no-network", env=env)
    assert result.returncode == 1
