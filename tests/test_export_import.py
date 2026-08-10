"""export_cache_json()/import_cache_json() and the --export/--import CLI flags."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "abuseipdb_proxy.py"


def run(*args, env=None, input=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=10, env=env, input=input,
    )


# --- export_cache_json() / import_cache_json() (unit level) ---------------

def test_export_round_trips_through_import(proxy):
    proxy.save_cache({
        "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
        "pending": {"5.6.7.8": {"due_time": 2000, "severity": 3,
                                 "categories": "15", "comment": "hacking"}},
        "retry_queue": {},
    })

    snapshot = proxy.export_cache_json()
    imported = proxy.import_cache_json(snapshot)

    assert imported == proxy.load_cache()


def test_export_includes_metadata(proxy):
    proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    data = json.loads(proxy.export_cache_json())

    assert data["format"] == "abuseipdb-proxy-cache-export"
    assert data["proxy_version"] == proxy.VERSION
    assert data["cache_backend"] == proxy.CACHE_BACKEND
    assert "exported_at" in data


def test_export_import_round_trips_between_two_separate_caches(make_proxy, tmp_path):
    source_proxy = make_proxy(ABUSEIPDB_CACHE_FILE=str(tmp_path / "source.db"))
    source_proxy.save_cache({"reports": {"1.1.1.1": {"time": 1, "severity": 1}},
                              "pending": {}, "retry_queue": {}})

    snapshot = source_proxy.export_cache_json()

    target_proxy = make_proxy(ABUSEIPDB_CACHE_FILE=str(tmp_path / "target.db"))
    imported = target_proxy.import_cache_json(snapshot)
    target_proxy.save_cache(imported)

    assert target_proxy.load_cache()["reports"] == {"1.1.1.1": {"time": 1, "severity": 1}}


def test_import_rejects_invalid_json(proxy):
    with pytest.raises(ValueError, match="not valid JSON"):
        proxy.import_cache_json("{not json")


def test_import_rejects_wrong_format_marker(proxy):
    with pytest.raises(ValueError, match="not a recognized cache export"):
        proxy.import_cache_json(json.dumps({"format": "something-else", "cache": {}}))


def test_import_rejects_missing_format_field_entirely(proxy):
    with pytest.raises(ValueError, match="not a recognized cache export"):
        proxy.import_cache_json(json.dumps({"reports": {}, "pending": {}, "retry_queue": {}}))


def test_import_rejects_incomplete_cache_section(proxy):
    with pytest.raises(ValueError, match="missing one of"):
        proxy.import_cache_json(json.dumps({
            "format": "abuseipdb-proxy-cache-export",
            "cache": {"reports": {}},  # missing pending/retry_queue
        }))


def test_import_tolerates_null_sections(proxy):
    # Defensive: a hand-edited export with explicit nulls shouldn't crash.
    imported = proxy.import_cache_json(json.dumps({
        "format": "abuseipdb-proxy-cache-export",
        "cache": {"reports": None, "pending": None, "retry_queue": None},
    }))
    assert imported == {"reports": {}, "pending": {}, "retry_queue": {}}


# --- CLI wiring (subprocess, end-to-end) -----------------------------------

def test_cli_export_to_stdout(tmp_path, monkeypatch):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    result = run("--export", env=env)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["format"] == "abuseipdb-proxy-cache-export"


def test_cli_export_to_file_then_import_round_trip(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "source.db")

    # Seed the source cache directly via the sqlite helper (no CLI flag for
    # writing a single entry — go straight to the storage layer).
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "source.db"))
    conn.execute("CREATE TABLE IF NOT EXISTS reports (ip TEXT PRIMARY KEY, time INTEGER NOT NULL, severity INTEGER NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS pending (ip TEXT PRIMARY KEY, due_time INTEGER NOT NULL, severity INTEGER NOT NULL, categories TEXT NOT NULL, comment TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS retry_queue (ip TEXT PRIMARY KEY, due_time INTEGER NOT NULL, categories TEXT NOT NULL, comment TEXT NOT NULL, attempts INTEGER NOT NULL)")
    conn.execute("INSERT INTO reports (ip, time, severity) VALUES ('9.9.9.9', 1, 1)")
    conn.commit()
    conn.close()

    export_path = tmp_path / "export.json"
    result = run("--export", str(export_path), env=env)
    assert result.returncode == 0
    assert export_path.exists()

    target_env = dict(env)
    target_env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "target.db")
    result = run("--import", str(export_path), "-y", env=target_env)
    assert result.returncode == 0

    conn = sqlite3.connect(str(tmp_path / "target.db"))
    imported = list(conn.execute("SELECT ip, time, severity FROM reports"))
    conn.close()
    assert imported == [("9.9.9.9", 1, 1)]


def test_cli_import_without_yes_prompts_and_aborts_on_no(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({
        "format": "abuseipdb-proxy-cache-export",
        "cache": {"reports": {"1.1.1.1": {"time": 1, "severity": 1}}, "pending": {}, "retry_queue": {}},
    }))

    result = run("--import", str(export_path), env=env, input="n\n")
    assert result.returncode == 1
    assert "Aborted" in result.stdout
    assert not (tmp_path / "cache.db").exists()  # nothing written


def test_cli_import_rejects_malformed_file(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    bad_path = tmp_path / "not-an-export.json"
    bad_path.write_text('{"hello": "world"}')

    result = run("--import", str(bad_path), "-y", env=env)
    assert result.returncode == 1
    assert "not a recognized cache export" in result.stderr


def test_cli_import_reports_missing_file_cleanly(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    result = run("--import", str(tmp_path / "does-not-exist.json"), "-y", env=env)
    assert result.returncode == 1
    assert "Import failed" in result.stderr
