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


def test_export_works_regardless_of_active_backend(make_proxy, tmp_path):
    sqlite_proxy = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(tmp_path / "c.db"))
    sqlite_proxy.save_cache({"reports": {"1.1.1.1": {"time": 1, "severity": 1}},
                              "pending": {}, "retry_queue": {}})

    snapshot = sqlite_proxy.export_cache_json()

    json_proxy = make_proxy(ABUSEIPDB_CACHE_BACKEND="json", ABUSEIPDB_CACHE_FILE=str(tmp_path / "c.json"))
    imported = json_proxy.import_cache_json(snapshot)
    json_proxy.save_cache(imported)

    assert json_proxy.load_cache()["reports"] == {"1.1.1.1": {"time": 1, "severity": 1}}


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
    env["ABUSEIPDB_CACHE_BACKEND"] = "json"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.json")

    result = run("--export", env=env)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["format"] == "abuseipdb-proxy-cache-export"


def test_cli_export_to_file_then_import_round_trip(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_BACKEND"] = "json"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "source.json")

    # Seed the source cache directly (no CLI flag for that — write it ourselves).
    (tmp_path / "source.json").write_text(json.dumps({
        "reports": {"9.9.9.9": {"time": 1, "severity": 1}}, "pending": {}, "retry_queue": {},
    }))

    export_path = tmp_path / "export.json"
    result = run("--export", str(export_path), env=env)
    assert result.returncode == 0
    assert export_path.exists()

    target_env = dict(env)
    target_env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "target.json")
    result = run("--import", str(export_path), "-y", env=target_env)
    assert result.returncode == 0

    imported = json.loads((tmp_path / "target.json").read_text())
    assert imported["reports"] == {"9.9.9.9": {"time": 1, "severity": 1}}


def test_cli_import_without_yes_prompts_and_aborts_on_no(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_BACKEND"] = "json"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.json")

    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({
        "format": "abuseipdb-proxy-cache-export",
        "cache": {"reports": {"1.1.1.1": {"time": 1, "severity": 1}}, "pending": {}, "retry_queue": {}},
    }))

    result = run("--import", str(export_path), env=env, input="n\n")
    assert result.returncode == 1
    assert "Aborted" in result.stdout
    assert not (tmp_path / "cache.json").exists()  # nothing written


def test_cli_import_rejects_malformed_file(tmp_path):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.json")

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
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.json")

    result = run("--import", str(tmp_path / "does-not-exist.json"), "-y", env=env)
    assert result.returncode == 1
    assert "Import failed" in result.stderr
