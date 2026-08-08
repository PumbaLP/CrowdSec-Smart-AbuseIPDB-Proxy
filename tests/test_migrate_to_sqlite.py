"""
Tests for --migrate-to-sqlite (and the ABUSEIPDB_CACHE_BACKEND=json
deprecation warnings around it) — the JSON backend is deprecated as of
2.9.0, slated for removal in 3.0.0. This is the migration path.
"""
import json
import sqlite3

import pytest


@pytest.fixture
def json_proxy_with_data(make_proxy, tmp_path):
    json_file = tmp_path / "cache.json"
    json_file.write_text(json.dumps({
        "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
        "pending": {"5.6.7.8": {"due_time": 2000, "severity": 3, "categories": "18", "comment": "x"}},
        "retry_queue": {},
    }))
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(json_file))
    return p, json_file


def test_migrate_writes_all_sections_to_sqlite(json_proxy_with_data):
    p, json_file = json_proxy_with_data
    result = p.run_migrate_to_sqlite()

    assert "error" not in result
    assert result["entries"] == 2
    assert result["source"] == str(json_file)

    conn = sqlite3.connect(result["target"])
    assert list(conn.execute("SELECT ip, time, severity FROM reports")) == [("1.2.3.4", 1000, 2)]
    assert list(conn.execute("SELECT ip FROM pending")) == [("5.6.7.8",)]


def test_migrate_default_target_replaces_json_extension_with_db(json_proxy_with_data):
    p, json_file = json_proxy_with_data
    result = p.run_migrate_to_sqlite()
    assert result["target"] == str(json_file).rsplit(".json", 1)[0] + ".db"


def test_migrate_accepts_explicit_target_path(json_proxy_with_data, tmp_path):
    p, json_file = json_proxy_with_data
    target = tmp_path / "custom.db"
    result = p.run_migrate_to_sqlite(target_path=str(target))
    assert result["target"] == str(target)
    assert target.exists()


def test_migrate_does_not_modify_or_delete_source_json(json_proxy_with_data):
    p, json_file = json_proxy_with_data
    original = json_file.read_text()
    p.run_migrate_to_sqlite()
    assert json_file.exists()
    assert json_file.read_text() == original


def test_migrate_refuses_to_overwrite_existing_target(json_proxy_with_data, tmp_path):
    p, json_file = json_proxy_with_data
    target = tmp_path / "existing.db"
    target.write_text("not really a db, just needs to exist")

    result = p.run_migrate_to_sqlite(target_path=str(target))

    assert "error" in result
    assert "already exists" in result["error"]
    assert target.read_text() == "not really a db, just needs to exist"  # untouched


def test_migrate_missing_source_file_errors_cleanly(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(tmp_path / "missing.json"))
    result = p.run_migrate_to_sqlite()
    assert "error" in result
    assert "missing.json" in result["error"]


def test_migrate_refuses_when_already_on_sqlite_backend(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))
    result = p.run_migrate_to_sqlite()
    assert "error" in result
    assert "already" in result["error"]


def test_migrate_handles_legacy_v1_flat_json_format(make_proxy, tmp_path):
    # v1.0.0 wrote a bare {ip: {"time", "severity"}} map with no
    # "reports"/"pending"/"retry_queue" wrapper at all
    json_file = tmp_path / "cache.json"
    json_file.write_text(json.dumps({"9.9.9.9": {"time": 500, "severity": 1}}))
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(json_file))

    result = p.run_migrate_to_sqlite()

    assert result["entries"] == 1
    conn = sqlite3.connect(result["target"])
    assert list(conn.execute("SELECT ip FROM reports")) == [("9.9.9.9",)]


def test_migrate_malformed_json_errors_cleanly(make_proxy, tmp_path):
    json_file = tmp_path / "cache.json"
    json_file.write_text("{not valid json")
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(json_file))

    result = p.run_migrate_to_sqlite()
    assert "error" in result


# --- Deprecation warnings --------------------------------------------------

def test_check_config_warns_on_json_backend(make_proxy, tmp_path, capsys):
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.json"))
    results = p.check_config()
    messages = [msg for level, msg in results if level == "warn"]
    assert any("deprecated" in m and "3.0.0" in m for m in messages)


def test_check_config_no_deprecation_warning_on_sqlite_backend(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))
    results = p.check_config()
    messages = [msg for level, msg in results if level == "warn"]
    assert not any("deprecated" in m for m in messages)
