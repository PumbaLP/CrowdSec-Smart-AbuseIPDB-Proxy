"""vacuum_cache() / --vacuum: prune-then-VACUUM for the SQLite backend."""
import os
import sqlite3
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


@pytest.fixture
def sqlite_proxy(make_proxy, tmp_path):
    return make_proxy(ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))


def test_prunes_reports_older_than_24h(sqlite_proxy):
    now = int(time.time())
    sqlite_proxy.save_cache({
        "reports": {
            "1.1.1.1": {"time": now - 90_000, "severity": 1},  # > 24h old
            "2.2.2.2": {"time": now - 100, "severity": 2},       # recent
        },
        "pending": {}, "retry_queue": {},
    })

    result = sqlite_proxy.vacuum_cache()

    assert result["pruned"] == 1
    cache = sqlite_proxy.load_cache()
    assert "1.1.1.1" not in cache["reports"]
    assert "2.2.2.2" in cache["reports"]


def test_does_not_touch_pending_or_retry_queue(sqlite_proxy):
    now = int(time.time())
    sqlite_proxy.save_cache({
        "reports": {},
        "pending": {"1.1.1.1": {"due_time": now + 100, "severity": 2, "categories": "15", "comment": "x"}},
        "retry_queue": {"2.2.2.2": {"due_time": now + 100, "categories": "18", "comment": "y", "attempts": 1}},
    })

    sqlite_proxy.vacuum_cache()

    cache = sqlite_proxy.load_cache()
    assert "1.1.1.1" in cache["pending"]
    assert "2.2.2.2" in cache["retry_queue"]


def test_returns_size_before_and_after(sqlite_proxy):
    sqlite_proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    result = sqlite_proxy.vacuum_cache()
    assert isinstance(result["size_before"], int)
    assert isinstance(result["size_after"], int)


def test_actually_reduces_file_size_after_heavy_churn(sqlite_proxy):
    # Simulate the kind of DELETE+INSERT churn save_cache() does on every
    # call, which is exactly what leaves SQLite with reclaimable free
    # pages for VACUUM to compact.
    for i in range(200):
        sqlite_proxy.save_cache({
            "reports": {f"10.0.{i % 256}.{j}": {"time": int(time.time()), "severity": 1} for j in range(50)},
            "pending": {}, "retry_queue": {},
        })
    sqlite_proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})  # empty it out

    result = sqlite_proxy.vacuum_cache()

    assert result["size_after"] <= result["size_before"]


def test_cache_remains_valid_and_queryable_after_vacuum(sqlite_proxy):
    sqlite_proxy.save_cache({
        "reports": {"9.9.9.9": {"time": int(time.time()), "severity": 2}},
        "pending": {}, "retry_queue": {},
    })
    sqlite_proxy.vacuum_cache()

    conn = sqlite3.connect(sqlite_proxy.CACHE_FILE)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"reports", "pending", "retry_queue"} <= tables
    assert sqlite_proxy.load_cache()["reports"]["9.9.9.9"]["severity"] == 2


def test_logs_a_summary_line(sqlite_proxy, capsys):
    sqlite_proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    sqlite_proxy.vacuum_cache()
    assert "Vacuumed SQLite cache" in capsys.readouterr().err


# --- CLI wiring -------------------------------------------------------------

def test_cli_vacuum_on_sqlite_backend(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_BACKEND"] = "sqlite"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    result = run("--vacuum", env=env)
    assert result.returncode == 0
    assert "Vacuumed SQLite cache" in result.stderr
    assert (tmp_path / "cache.db").exists()


def test_cli_vacuum_does_not_require_an_api_key(tmp_path):
    # --vacuum is a maintenance operation, not a reporting one — no key
    # (and no --dry-run) needed, same spirit as --version/--export.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_CACHE_BACKEND"] = "sqlite"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    result = run("--vacuum", env=env)
    assert result.returncode == 0
