"""check_config()/format_config_check() and the --check-config CLI flag."""
import json as jsonlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "abuseipdb_proxy.py"


def run(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=10, env=env,
    )


def _levels(results):
    return [level for level, _ in results]


# --- check_config() (unit level) --------------------------------------------

def test_all_ok_in_a_clean_dry_run_config(proxy):
    results = proxy.check_config()
    assert "fail" not in _levels(results)


def test_missing_api_key_without_dry_run_fails(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false")
    monkeypatch.setattr(p, "API_KEY", None)
    results = p.check_config()
    assert any(level == "fail" and "ABUSEIPDB_API_KEY" in msg for level, msg in results)


def test_short_api_key_warns(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false")
    monkeypatch.setattr(p, "API_KEY", "short")
    results = p.check_config()
    assert any(level == "warn" and "API_KEY" in msg for level, msg in results)


def test_cache_backend_no_longer_json_warns_but_still_runs(make_proxy, tmp_path):
    # ABUSEIPDB_CACHE_BACKEND was removed in 3.0.0 (sqlite is the only
    # option now) — an old env file still setting it to "json" (or
    # anything else) must not be fatal, just loudly warned about.
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))
    results = p.check_config()
    assert any(level == "warn" and "no longer supported" in msg for level, msg in results)
    assert not any(level == "fail" and "CACHE_BACKEND" in msg for level, msg in results)
    assert p.CACHE_BACKEND == "sqlite"


def test_unwritable_cache_dir_fails(proxy, monkeypatch, tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    monkeypatch.setattr(proxy, "CACHE_FILE", str(blocker / "cache.db"))
    results = proxy.check_config()
    assert any(level == "fail" and "writable" in msg.lower() or "created" in msg.lower()
               for level, msg in results)


def test_out_of_range_port_fails(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "LISTEN_PORT", 99999)
    results = proxy.check_config()
    assert any(level == "fail" and "PROXY_PORT" in msg for level, msg in results)


def test_non_loopback_listen_address_warns_outside_dry_run(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false", ABUSEIPDB_LISTEN_ADDRESS="0.0.0.0")
    monkeypatch.setattr(p, "API_KEY", "x" * 40)  # keep the API key check from also failing
    results = p.check_config()
    assert any(level == "warn" and "LISTEN_ADDRESS" in msg for level, msg in results)


def test_zero_or_negative_report_window_fails(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "REPORT_WINDOWS", {1: 0, 2: 905, 3: 905})
    results = proxy.check_config()
    assert any(level == "fail" and "REPORT_WINDOW_LOW" in msg for level, msg in results)


def test_report_windows_out_of_order_warns(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "REPORT_WINDOWS", {1: 1000, 2: 500, 3: 200})
    results = proxy.check_config()
    assert any(level == "warn" and "order" in msg for level, msg in results)


def test_max_retries_below_one_fails(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_RETRIES", 0)
    results = proxy.check_config()
    assert any(level == "fail" and "MAX_RETRIES" in msg for level, msg in results)


def test_no_backend_configured_warns_not_fails(proxy):
    results = proxy.check_config()
    assert any(level == "warn" and "No alerting backend" in msg for level, msg in results)
    assert not any("alerting backend" in msg.lower() and level == "fail" for level, msg in results)


def test_fully_configured_backend_is_ok(make_proxy):
    p = make_proxy(ABUSEIPDB_GOTIFY_URL="https://gotify.example.com", ABUSEIPDB_GOTIFY_TOKEN="t")
    results = p.check_config()
    assert any(level == "ok" and "Gotify" in msg for level, msg in results)
    assert not any(level == "fail" for level, _ in results)


@pytest.mark.parametrize("env_overrides", [
    {"ABUSEIPDB_GOTIFY_URL": "https://gotify.example.com"},  # missing token
    {"ABUSEIPDB_MATRIX_HOMESERVER_URL": "https://matrix.example.com"},  # missing token+room
    {"ABUSEIPDB_TELEGRAM_BOT_TOKEN": "t"},  # missing chat id
    {"ABUSEIPDB_HOMEASSISTANT_URL": "https://ha.example.com"},  # missing token
])
def test_partially_configured_backend_fails(make_proxy, env_overrides):
    p = make_proxy(**env_overrides)
    results = p.check_config()
    assert any(level == "fail" and "partially configured" in msg for level, msg in results)


def test_malformed_webhook_url_fails(make_proxy):
    p = make_proxy(ABUSEIPDB_WEBHOOK_URL="not-a-url")
    results = p.check_config()
    assert any(level == "fail" and "webhook" in msg for level, msg in results)


def test_valid_webhook_url_is_ok(make_proxy):
    p = make_proxy(ABUSEIPDB_WEBHOOK_URL="https://example.com/hook")
    results = p.check_config()
    assert any(level == "ok" and "webhook" in msg for level, msg in results)


def test_sqlite_pragma_summary_always_shown(proxy):
    # SQLite is the only cache backend since 3.0.0 — no more conditional
    # display depending on which backend happened to be active.
    assert any("SQLite pragmas:" in msg for _, msg in proxy.check_config())


# --- format_config_check() ---------------------------------------------------

def test_format_shows_symbols_per_level(proxy):
    text = proxy.format_config_check([("ok", "a"), ("warn", "b"), ("fail", "c")])
    assert "[OK]" in text
    assert "[WARN]" in text
    assert "[FAIL]" in text


def test_format_all_ok_summary(proxy):
    text = proxy.format_config_check([("ok", "a"), ("ok", "b")])
    assert "All checks passed." in text


def test_format_counts_problems_and_warnings(proxy):
    text = proxy.format_config_check([("fail", "a"), ("fail", "b"), ("warn", "c"), ("ok", "d")])
    assert "2 problem(s), 1 warning(s)" in text


# --- CLI wiring --------------------------------------------------------------

def _base_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    env.update(extra)
    return env


def test_cli_check_config_exits_zero_when_clean(tmp_path):
    result = run("--check-config", env=_base_env(tmp_path))
    assert result.returncode == 0
    assert "[FAIL]" not in result.stdout


def test_cli_check_config_exits_one_on_failure(tmp_path):
    env = _base_env(tmp_path)
    del env["ABUSEIPDB_DRY_RUN"]  # no dry-run, no API key -> a real failure
    result = run("--check-config", env=env)
    assert result.returncode == 1
    assert "[FAIL]" in result.stdout


def test_cli_check_config_json_output(tmp_path):
    result = run("--check-config", "--json", env=_base_env(tmp_path))
    assert result.returncode == 0
    data = jsonlib.loads(result.stdout)
    assert isinstance(data, list)
    assert all({"level", "message"} <= set(item) for item in data)


def test_cli_check_config_does_not_require_dry_run_to_run_at_all(tmp_path):
    # It should always run (that's the point) — just report a FAIL for
    # the missing key rather than refusing to check anything.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    result = run("--check-config", env=env)
    assert "[FAIL]" in result.stdout
    assert result.returncode == 1


def test_cli_check_config_respects_dry_run_flag_not_just_env_var(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    result = run("--check-config", "--dry-run", env=env)
    assert "not required" in result.stdout
    assert result.returncode == 0
