"""run_backup(): timestamped cache snapshots with retention pruning, and --backup."""
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


def test_default_backup_dir_is_next_to_the_cache_file(proxy, tmp_path):
    result = proxy.run_backup()
    expected_dir = os.path.join(os.path.dirname(proxy.CACHE_FILE), "backups")
    assert os.path.dirname(result["backup_path"]) == expected_dir
    assert os.path.exists(result["backup_path"])


def test_custom_backup_dir_is_used_and_created(proxy, tmp_path):
    custom_dir = str(tmp_path / "my-backups")
    result = proxy.run_backup(backup_dir=custom_dir)
    assert result["backup_path"].startswith(custom_dir)
    assert os.path.isdir(custom_dir)


def test_backup_content_matches_export_format(proxy):
    proxy.save_cache({"reports": {"1.1.1.1": {"time": 1, "severity": 2}}, "pending": {}, "retry_queue": {}})
    result = proxy.run_backup()
    with open(result["backup_path"]) as f:
        data = jsonlib.load(f)
    assert data["format"] == "abuseipdb-proxy-cache-export"
    assert data["cache"]["reports"] == {"1.1.1.1": {"time": 1, "severity": 2}}


def test_retention_keeps_only_the_configured_count(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_BACKUP_RETENTION="3")
    backup_dir = str(tmp_path / "backups")
    for i in range(5):
        p.run_backup(backup_dir=backup_dir)
        time.sleep(1.01)  # timestamps have 1-second resolution

    files = sorted(f for f in os.listdir(backup_dir) if f.startswith("cache-"))
    assert len(files) == 3


def test_retention_keeps_the_newest_ones(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_BACKUP_RETENTION="2")
    backup_dir = str(tmp_path / "backups")
    paths = []
    for i in range(4):
        result = p.run_backup(backup_dir=backup_dir)
        paths.append(result["backup_path"])
        time.sleep(1.01)

    remaining = sorted(os.listdir(backup_dir))
    # the two oldest (paths[0], paths[1]) should be gone, the two newest kept
    assert os.path.basename(paths[-1]) in remaining
    assert os.path.basename(paths[-2]) in remaining
    assert os.path.basename(paths[0]) not in remaining


def test_retention_default_is_14(proxy):
    assert proxy.BACKUP_RETENTION == 14


def test_retention_configurable(make_proxy):
    p = make_proxy(ABUSEIPDB_BACKUP_RETENTION="30")
    assert p.BACKUP_RETENTION == 30


def test_negative_retention_falls_back_to_zero_not_a_crash(make_proxy):
    # run_backup()'s pruning loop is `while len(existing) > BACKUP_RETENTION:
    # existing.pop(0)` -- a negative retention keeps that condition true
    # even once the list is already empty (0 > -1), so the next pop(0)
    # would raise IndexError. Must fail closed to 0 ("keep no backups")
    # instead of crashing --backup / the backup timer.
    p = make_proxy(ABUSEIPDB_BACKUP_RETENTION="-1")
    assert p.BACKUP_RETENTION == 0


def test_run_backup_does_not_crash_with_retention_forced_negative(make_proxy, tmp_path):
    # Belt-and-suspenders: even if BACKUP_RETENTION's own guard were ever
    # bypassed (e.g. a future caller sets the module attribute directly),
    # run_backup() itself must not crash pruning down to an already-empty
    # backup directory. A negative value floors to 0 ("keep no backups"),
    # so the backup just written gets pruned again immediately too --
    # that's the correct behavior for retention=0, not a bug; the actual
    # thing under test here is that this doesn't raise IndexError.
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="x")
    p.save_cache({"reports": {"1.2.3.4": {"time": 1, "severity": 1}}, "pending": {}, "retry_queue": {}})
    p.BACKUP_RETENTION = -1
    backup_dir = str(tmp_path / "backups")

    result = p.run_backup(backup_dir=backup_dir)  # must not raise

    assert result["retention"] == 0
    assert os.listdir(backup_dir) == []  # the one backup written was pruned right back out, as expected for retention=0


def test_reports_pruned_filenames(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_BACKUP_RETENTION="1")
    backup_dir = str(tmp_path / "backups")
    p.run_backup(backup_dir=backup_dir)
    time.sleep(1.01)
    result = p.run_backup(backup_dir=backup_dir)
    assert len(result["pruned"]) == 1


def test_does_not_touch_unrelated_files_in_the_backup_dir(proxy, tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    (backup_dir / "readme.txt").write_text("do not delete me")
    proxy.run_backup(backup_dir=str(backup_dir))
    assert (backup_dir / "readme.txt").exists()


def test_two_backups_within_the_same_second_do_not_overwrite_each_other(proxy, tmp_path, monkeypatch):
    # The timestamp-based filename only has 1-second resolution -- freeze
    # "now" so both calls land on the exact same second (simulating two
    # back-to-back invocations), and confirm the second one gets a
    # distinct filename rather than silently clobbering the first backup.
    fixed_now = proxy.datetime(2026, 1, 1, 12, 0, 0, tzinfo=proxy.timezone.utc)

    class FrozenDatetime(proxy.datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    monkeypatch.setattr(proxy, "datetime", FrozenDatetime)
    backup_dir = str(tmp_path / "backups")

    first = proxy.run_backup(backup_dir=backup_dir)
    proxy.save_cache({"reports": {"1.2.3.4": {"time": 1, "severity": 1}}, "pending": {}, "retry_queue": {}})
    second = proxy.run_backup(backup_dir=backup_dir)

    assert first["backup_path"] != second["backup_path"]
    assert os.path.exists(first["backup_path"])
    assert os.path.exists(second["backup_path"])
    # And the first backup's content wasn't clobbered by the second's.
    with open(first["backup_path"]) as f:
        first_content = f.read()
    assert "1.2.3.4" not in first_content


def test_logs_the_backup_path(proxy, capsys):
    result = proxy.run_backup()
    captured = capsys.readouterr()
    assert result["backup_path"] in captured.err


# --- CLI wiring --------------------------------------------------------------

def _base_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_DRY_RUN"] = "true"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    env.update(extra)
    return env


def test_cli_backup_default_dir(tmp_path):
    result = run("--backup", env=_base_env(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "backups").is_dir()
    assert len(list((tmp_path / "backups").glob("cache-*.json"))) == 1


def test_cli_backup_custom_dir(tmp_path):
    custom = tmp_path / "elsewhere"
    result = run("--backup", str(custom), env=_base_env(tmp_path))
    assert result.returncode == 0
    assert len(list(custom.glob("cache-*.json"))) == 1


def test_cli_backup_json_output(tmp_path):
    result = run("--backup", "--json", env=_base_env(tmp_path))
    data = jsonlib.loads(result.stdout)
    assert "backup_path" in data
    assert "retention" in data


def test_cli_backup_does_not_require_an_api_key(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")
    result = run("--backup", env=env)
    assert result.returncode == 0
