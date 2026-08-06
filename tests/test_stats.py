"""build_stats()/format_stats_text() and the --stats/--stats-limit/--json CLI flags."""
import json as jsonlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "abuseipdb_proxy.py"


def run(*args, env=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=10, env=env,
    )


# --- build_stats() (unit level) --------------------------------------------

def test_empty_cache(proxy):
    stats = proxy.build_stats()
    assert stats["reports_tracked"] == 0
    assert stats["recent_reports"] == []
    assert stats["pending_escalations"] == []
    assert stats["queued_retries"] == []


def test_reports_by_severity_breakdown(proxy):
    proxy.save_cache({
        "reports": {
            "1.1.1.1": {"time": int(time.time()), "severity": 1},
            "2.2.2.2": {"time": int(time.time()), "severity": 1},
            "3.3.3.3": {"time": int(time.time()), "severity": 2},
            "4.4.4.4": {"time": int(time.time()), "severity": 3},
        },
        "pending": {}, "retry_queue": {},
    })
    stats = proxy.build_stats()
    assert stats["reports_by_severity"] == {"low": 2, "medium": 1, "high": 1}
    assert stats["reports_tracked"] == 4


def test_recent_reports_sorted_newest_first(proxy):
    now = int(time.time())
    proxy.save_cache({
        "reports": {
            "old.ip": {"time": now - 1000, "severity": 1},
            "new.ip": {"time": now - 10, "severity": 2},
        },
        "pending": {}, "retry_queue": {},
    })
    stats = proxy.build_stats()
    assert [r["ip"] for r in stats["recent_reports"]] == ["new.ip", "old.ip"]


def test_stats_limit_caps_recent_reports(proxy):
    now = int(time.time())
    proxy.save_cache({
        "reports": {f"1.2.3.{i}": {"time": now - i, "severity": 1} for i in range(20)},
        "pending": {}, "retry_queue": {},
    })
    stats = proxy.build_stats(limit=3)
    assert len(stats["recent_reports"]) == 3


def test_pending_and_retries_are_included(proxy):
    now = int(time.time())
    proxy.save_cache({
        "reports": {},
        "pending": {"9.9.9.9": {"due_time": now + 100, "severity": 3, "categories": "15", "comment": "x"}},
        "retry_queue": {"8.8.8.8": {"due_time": now + 200, "categories": "18", "comment": "y", "attempts": 2}},
    })
    stats = proxy.build_stats()
    assert stats["pending_escalations"] == [
        {"ip": "9.9.9.9", "due_time": now + 100, "severity": 3, "categories": "15"}
    ]
    assert stats["queued_retries"] == [
        {"ip": "8.8.8.8", "due_time": now + 200, "attempts": 2}
    ]


def test_quota_unknown_when_never_updated(proxy):
    stats = proxy.build_stats()
    assert stats["abuseipdb_quota"] == {"limit": None, "remaining": None, "updated_at": None}


def test_quota_reflects_the_persisted_sidecar_file(proxy):
    proxy._update_quota_from_headers({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "500"})
    stats = proxy.build_stats()
    assert stats["abuseipdb_quota"]["limit"] == 1000
    assert stats["abuseipdb_quota"]["remaining"] == 500


def test_quota_survives_a_fresh_module_reimport(make_proxy, tmp_path):
    # The whole point: --stats runs as a separate process from the live
    # service, so in-memory quota_state alone (reset on reimport, same as
    # a fresh process) must not be the only source of truth.
    db_path = tmp_path / "cache.db"
    p1 = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
    p1._update_quota_from_headers({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "42"})

    p2 = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
    assert p2.quota_state == {"limit": None, "remaining": None, "updated_at": None}  # fresh in-memory state
    assert p2.load_quota_state()["remaining"] == 42  # but the persisted snapshot is there


def test_quota_sidecar_write_failure_does_not_raise(proxy, tmp_path, monkeypatch):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    monkeypatch.setattr(proxy, "QUOTA_STATE_FILE", str(blocker / "quota.json"))
    proxy._update_quota_from_headers({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "1"})  # must not raise
    assert proxy.quota_state["remaining"] == 1  # in-memory update still succeeded


def test_load_quota_state_tolerates_a_missing_file(proxy):
    assert proxy.load_quota_state() == {"limit": None, "remaining": None, "updated_at": None}


def test_load_quota_state_tolerates_a_corrupt_file(proxy):
    with open(proxy.QUOTA_STATE_FILE, "w") as f:
        f.write("{not valid json")
    assert proxy.load_quota_state() == {"limit": None, "remaining": None, "updated_at": None}


# --- format_stats_text() ----------------------------------------------------

def test_text_format_includes_backend_and_counts(proxy):
    proxy.save_cache({"reports": {"1.1.1.1": {"time": int(time.time()), "severity": 3}},
                       "pending": {}, "retry_queue": {}})
    text = proxy.format_stats_text(proxy.build_stats())
    assert "1.1.1.1" in text
    assert "high" in text
    assert proxy.CACHE_BACKEND in text


def test_text_format_handles_the_all_empty_case(proxy):
    text = proxy.format_stats_text(proxy.build_stats())
    assert "No reports currently tracked." in text
    assert "Pending escalations: none" in text
    assert "Queued retries: none" in text
    assert "quota: unknown" in text


# --- CLI wiring --------------------------------------------------------------

def _base_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_BACKEND"] = "sqlite"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    env.update(extra)
    return env


def test_cli_stats_text_output(tmp_path):
    result = run("--stats", env=_base_env(tmp_path))
    assert result.returncode == 0
    assert "Cache Stats" in result.stdout


def test_cli_stats_json_output(tmp_path):
    result = run("--stats", "--json", env=_base_env(tmp_path))
    assert result.returncode == 0
    data = jsonlib.loads(result.stdout)
    assert "reports_tracked" in data
    assert "abuseipdb_quota" in data


def test_cli_stats_limit(tmp_path):
    env = _base_env(tmp_path)
    seed = tmp_path / "seed.py"
    seed_source = (
        "import importlib.util, time\n"
        "spec = importlib.util.spec_from_file_location('abuseipdb_proxy', SCRIPT_PATH)\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        "now = int(time.time())\n"
        "m.save_cache({\n"
        "    'reports': {f'1.2.3.{i}': {'time': now - i, 'severity': 1} for i in range(20)},\n"
        "    'pending': {}, 'retry_queue': {},\n"
        "})\n"
    ).replace("SCRIPT_PATH", repr(str(SCRIPT)))
    seed.write_text(seed_source)
    subprocess.run([sys.executable, str(seed)], env=env, check=True, timeout=10)

    result = run("--stats", "--json", "--stats-limit", "3", env=env)
    data = jsonlib.loads(result.stdout)
    assert len(data["recent_reports"]) == 3
    assert data["reports_tracked"] == 20  # the cap only applies to the recent-list, not the total count


def test_cli_stats_does_not_require_dry_run_or_real_key(tmp_path):
    # --stats is read-only against the cache, same spirit as --version/--vacuum/--export.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_CACHE_BACKEND"] = "sqlite"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    result = run("--stats", env=env)
    assert result.returncode == 0
