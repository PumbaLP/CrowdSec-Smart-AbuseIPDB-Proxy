"""
Tests for --migrate-to-sqlite. As of 3.0.0, the JSON cache backend was
removed entirely — this now takes an explicit source path rather than
reading ABUSEIPDB_CACHE_BACKEND/ABUSEIPDB_CACHE_FILE, since there's
nothing for those to point at anymore.
"""
import json
import sqlite3
from contextlib import closing

import pytest


@pytest.fixture
def json_cache_file(tmp_path):
    json_file = tmp_path / "cache.json"
    json_file.write_text(json.dumps({
        "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
        "pending": {"5.6.7.8": {"due_time": 2000, "severity": 3, "categories": "18", "comment": "x"}},
        "retry_queue": {},
    }))
    return json_file


def test_migrate_writes_all_sections_to_sqlite(proxy, json_cache_file):
    result = proxy.run_migrate_to_sqlite(str(json_cache_file))

    assert "error" not in result
    assert result["entries"] == 2
    assert result["source"] == str(json_cache_file)

    with closing(sqlite3.connect(result["target"])) as conn:
        assert list(conn.execute("SELECT ip, time, severity FROM reports")) == [("1.2.3.4", 1000, 2)]
        assert list(conn.execute("SELECT ip FROM pending")) == [("5.6.7.8",)]


def test_migrate_default_target_replaces_json_extension_with_db(proxy, json_cache_file):
    result = proxy.run_migrate_to_sqlite(str(json_cache_file))
    assert result["target"] == str(json_cache_file).rsplit(".json", 1)[0] + ".db"


def test_migrate_accepts_explicit_target_path(proxy, json_cache_file, tmp_path):
    target = tmp_path / "custom.db"
    result = proxy.run_migrate_to_sqlite(str(json_cache_file), target_path=str(target))
    assert result["target"] == str(target)
    assert target.exists()


def test_migrate_does_not_modify_or_delete_source_json(proxy, json_cache_file):
    original = json_cache_file.read_text()
    proxy.run_migrate_to_sqlite(str(json_cache_file))
    assert json_cache_file.exists()
    assert json_cache_file.read_text() == original


def test_migrate_refuses_to_overwrite_existing_target(proxy, json_cache_file, tmp_path):
    target = tmp_path / "existing.db"
    target.write_text("not really a db, just needs to exist")

    result = proxy.run_migrate_to_sqlite(str(json_cache_file), target_path=str(target))

    assert "error" in result
    assert "already exists" in result["error"]
    assert target.read_text() == "not really a db, just needs to exist"  # untouched


def test_migrate_missing_source_file_errors_cleanly(proxy, tmp_path):
    result = proxy.run_migrate_to_sqlite(str(tmp_path / "missing.json"))
    assert "error" in result
    assert "missing.json" in result["error"]


def test_migrate_source_without_json_extension_gets_db_suffix_appended(proxy, tmp_path):
    # source with no extension at all (unusual, but shouldn't crash or
    # silently overwrite the source itself)
    source = tmp_path / "cache"
    source.write_text(json.dumps({"reports": {}, "pending": {}, "retry_queue": {}}))
    result = proxy.run_migrate_to_sqlite(str(source))
    assert result["target"] == str(source) + ".db"


def test_migrate_handles_legacy_v1_flat_json_format(proxy, tmp_path):
    # v1.0.0 wrote a bare {ip: {"time", "severity"}} map with no
    # "reports"/"pending"/"retry_queue" wrapper at all
    json_file = tmp_path / "cache.json"
    json_file.write_text(json.dumps({"9.9.9.9": {"time": 500, "severity": 1}}))

    result = proxy.run_migrate_to_sqlite(str(json_file))

    assert result["entries"] == 1
    with closing(sqlite3.connect(result["target"])) as conn:
        assert list(conn.execute("SELECT ip FROM reports")) == [("9.9.9.9",)]


def test_migrate_malformed_json_errors_cleanly(proxy, tmp_path):
    json_file = tmp_path / "cache.json"
    json_file.write_text("{not valid json")

    result = proxy.run_migrate_to_sqlite(str(json_file))
    assert "error" in result


# --- ABUSEIPDB_CACHE_BACKEND removal (3.0.0) --------------------------------

def test_leftover_cache_backend_json_warns_but_keeps_running(make_proxy, tmp_path):
    # An old env file still setting ABUSEIPDB_CACHE_BACKEND=json (from
    # before 3.0.0) must degrade to a loud warning, not break startup —
    # sqlite is the only backend now regardless of what this says.
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))
    results = p.check_config()
    messages = [msg for level, msg in results if level == "warn"]
    assert any("no longer supported" in m for m in messages)
    assert p.CACHE_BACKEND == "sqlite"


def test_no_warning_when_cache_backend_is_unset(proxy):
    results = proxy.check_config()
    messages = [msg for level, msg in results if level == "warn"]
    assert not any("no longer supported" in m for m in messages)


def test_cache_file_ending_in_json_is_redirected_to_db(make_proxy, tmp_path):
    # A leftover ABUSEIPDB_CACHE_FILE=.../cache.json must never be opened
    # as a SQLite database — silently trying would either crash or (worse)
    # corrupt/misinterpret the old JSON file.
    p = make_proxy(ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.json"))
    assert p.CACHE_FILE == str(tmp_path / "cache.db")
