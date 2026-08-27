"""load_cache() / save_cache() with ABUSEIPDB_CACHE_BACKEND=sqlite."""
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import _load_fresh_module


@pytest.fixture
def sqlite_proxy(make_proxy, tmp_path):
    return make_proxy(
        ABUSEIPDB_CACHE_BACKEND="sqlite",
        ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"),
    )


def test_default_cache_filename_is_db_not_json(monkeypatch, tmp_path):
    # make_proxy() always supplies its own default ABUSEIPDB_CACHE_FILE
    # for test isolation, so it can't be used to observe the module's
    # *own* backend-appropriate default — load it directly instead, with
    # everything module-level reading from a clean env except the two
    # variables under test.
    for var in ("ABUSEIPDB_CACHE_FILE", "ABUSEIPDB_CACHE_BACKEND"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setenv("ABUSEIPDB_CACHE_BACKEND", "sqlite")
    monkeypatch.chdir(tmp_path)  # in case anything relative sneaks in

    p = _load_fresh_module()

    assert p.CACHE_FILE.endswith("cache.db")
    assert p.CACHE_FILE != "/var/lib/abuseipdb-proxy/cache.json"


def test_sqlite_pragmas_default_to_wal_and_normal(sqlite_proxy):
    assert sqlite_proxy.CACHE_SQLITE_JOURNAL_MODE == "WAL"
    assert sqlite_proxy.CACHE_SQLITE_SYNCHRONOUS == "NORMAL"


def test_sqlite_pragmas_are_configurable(make_proxy, tmp_path):
    p = make_proxy(
        ABUSEIPDB_CACHE_BACKEND="sqlite",
        ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"),
        ABUSEIPDB_SQLITE_JOURNAL_MODE="delete",  # lowercase on purpose: must be normalized
        ABUSEIPDB_SQLITE_SYNCHRONOUS="full",
    )
    assert p.CACHE_SQLITE_JOURNAL_MODE == "DELETE"
    assert p.CACHE_SQLITE_SYNCHRONOUS == "FULL"

    # Actually takes effect, not just parsed.
    p.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    conn = sqlite3.connect(p.CACHE_FILE)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    conn.close()


def test_invalid_pragma_value_falls_back_to_the_safe_default(make_proxy, tmp_path, capsys):
    p = make_proxy(
        ABUSEIPDB_CACHE_BACKEND="sqlite",
        ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"),
        ABUSEIPDB_SQLITE_SYNCHRONOUS="YOLO",
    )
    assert p.CACHE_SQLITE_SYNCHRONOUS == "NORMAL"  # not "YOLO" — that's not a real PRAGMA value


def test_invalid_cache_backend_value_falls_back_to_sqlite_not_silently_mismatched(make_proxy, tmp_path, capsys):
    # A typo like "sqllite" must not silently fall through to the JSON
    # code path against a .db-named file (or vice versa) — that would
    # mean reading/writing garbage without any warning.
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqllite", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))
    assert p.CACHE_BACKEND == "sqlite"
    p.save_cache({"reports": {"1.1.1.1": {"time": 1, "severity": 1}}, "pending": {}, "retry_queue": {}})
    assert p.load_cache()["reports"] == {"1.1.1.1": {"time": 1, "severity": 1}}


def test_sqlite_is_the_true_module_default_with_no_env_var_set(monkeypatch, tmp_path):
    # Not even ABUSEIPDB_CACHE_BACKEND is set here — this is what a
    # fresh v2.0.0 install actually sees.
    for var in ("ABUSEIPDB_CACHE_FILE", "ABUSEIPDB_CACHE_BACKEND"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")

    p = _load_fresh_module()

    assert p.CACHE_BACKEND == "sqlite"
    assert p.CACHE_FILE.endswith("cache.db")


def test_missing_db_returns_empty_structure(sqlite_proxy):
    assert sqlite_proxy.load_cache() == {"reports": {}, "pending": {}, "retry_queue": {}}


def test_save_then_load_round_trips(sqlite_proxy):
    cache = {
        "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
        "pending": {"5.6.7.8": {"due_time": 2000, "severity": 3,
                                 "categories": "15", "comment": "hacking"}},
        "retry_queue": {"9.9.9.9": {"due_time": 3000, "categories": "18",
                                     "comment": "brute-force", "attempts": 2}},
    }
    sqlite_proxy.save_cache(cache)
    loaded = sqlite_proxy.load_cache()
    assert loaded["reports"] == cache["reports"]
    # save_cache() didn't receive a created_at for these (a caller
    # building the dict by hand, same as this test) -- it must fall back
    # to "now" rather than persisting NULL, and load_cache() must then
    # round-trip that fallback value back out.
    assert loaded["pending"]["5.6.7.8"]["created_at"] is not None
    assert loaded["retry_queue"]["9.9.9.9"]["created_at"] is not None
    for key in ("due_time", "severity", "categories", "comment"):
        assert loaded["pending"]["5.6.7.8"][key] == cache["pending"]["5.6.7.8"][key]
    for key in ("due_time", "categories", "comment", "attempts"):
        assert loaded["retry_queue"]["9.9.9.9"][key] == cache["retry_queue"]["9.9.9.9"][key]


def test_save_then_load_round_trips_an_explicit_created_at(sqlite_proxy):
    # When the caller DOES supply created_at (e.g. re-importing a backup,
    # or load_cache()'s own output being fed straight back to
    # save_cache()), that value must be preserved, not silently
    # overwritten with "now" -- the "now" fallback above is specifically
    # for when it's *missing*, not a blanket reset on every save.
    cache = {
        "reports": {},
        "pending": {"5.6.7.8": {"due_time": 2000, "severity": 3,
                                 "categories": "15", "comment": "hacking",
                                 "created_at": 500}},
        "retry_queue": {"9.9.9.9": {"due_time": 3000, "categories": "18",
                                     "comment": "brute-force", "attempts": 2,
                                     "created_at": 600}},
    }
    sqlite_proxy.save_cache(cache)
    loaded = sqlite_proxy.load_cache()
    assert loaded["pending"]["5.6.7.8"]["created_at"] == 500
    assert loaded["retry_queue"]["9.9.9.9"]["created_at"] == 600


def test_vacuum_preserves_created_at_for_surviving_pending_retry_rows(sqlite_proxy):
    # Regression test: vacuum_cache() (and --backup/--import, anything
    # going through the bulk load_cache()+save_cache() round trip rather
    # than the per-alert single-row helpers) used to silently NULL out
    # every pending/retry row's created_at on every single call, quietly
    # resetting /health's age tracking for anything that survived a
    # vacuum run -- confirmed by first reproducing this against the
    # unfixed code before writing this test.
    sqlite_proxy._sqlite_upsert_pending("1.2.3.4", due_time=999999999999, severity=1,
                                         categories="14", comment="x")
    age_before = sqlite_proxy._oldest_entry_age("pending")
    assert age_before is not None

    sqlite_proxy.vacuum_cache()

    age_after = sqlite_proxy._oldest_entry_age("pending")
    assert age_after is not None
    assert age_after < 5  # still a real, recent timestamp -- not None/reset


def test_save_replaces_previous_contents_entirely(sqlite_proxy):
    # save_cache() always receives the full desired state (same contract
    # as the JSON backend) — a second save must fully replace the first,
    # not merge into it.
    sqlite_proxy.save_cache({
        "reports": {"1.2.3.4": {"time": 1000, "severity": 1}},
        "pending": {}, "retry_queue": {},
    })
    sqlite_proxy.save_cache({
        "reports": {"5.6.7.8": {"time": 2000, "severity": 3}},
        "pending": {}, "retry_queue": {},
    })

    cache = sqlite_proxy.load_cache()
    assert cache["reports"] == {"5.6.7.8": {"time": 2000, "severity": 3}}


def test_creates_the_expected_schema(sqlite_proxy):
    sqlite_proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    conn = sqlite3.connect(sqlite_proxy.CACHE_FILE)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"reports", "pending", "retry_queue"} <= tables


def test_corrupt_db_file_falls_back_to_empty_structure(sqlite_proxy):
    with open(sqlite_proxy.CACHE_FILE, "wb") as f:
        f.write(b"this is not a sqlite database")
    assert sqlite_proxy.load_cache() == {"reports": {}, "pending": {}, "retry_queue": {}}


def test_write_failure_triggers_one_high_priority_notification(sqlite_proxy, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(sqlite_proxy, "notify", lambda msg, priority="high": calls.append((msg, priority)))
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    monkeypatch.setattr(sqlite_proxy, "CACHE_FILE", str(blocker / "cache.db"))

    sqlite_proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    sqlite_proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})

    assert len(calls) == 1
    assert calls[0][1] == "high"


def test_two_independent_caches_in_different_directories_do_not_share_state(make_proxy, tmp_path):
    dir_a = tmp_path / "a"
    dir_a.mkdir()
    dir_b = tmp_path / "b"
    dir_b.mkdir()

    proxy_a = make_proxy(ABUSEIPDB_CACHE_FILE=str(dir_a / "cache.db"))
    proxy_a.save_cache({"reports": {"1.2.3.4": {"time": 1, "severity": 1}},
                         "pending": {}, "retry_queue": {}})

    proxy_b = make_proxy(ABUSEIPDB_CACHE_FILE=str(dir_b / "cache.db"))
    assert proxy_b.load_cache() == {"reports": {}, "pending": {}, "retry_queue": {}}


class TestJsonToSqliteMigration:
    """
    v2.0.0 made SQLite the default backend. On upgrade, an existing
    installation has a real v1.x cache.json sitting right next to where
    the new cache.db will be created — that history must survive the
    upgrade automatically, without the user having to do anything.
    """

    def _legacy_json_path(self, cache_file):
        import os
        return os.path.join(os.path.dirname(cache_file), "cache.json")

    def test_legacy_json_is_imported_into_a_fresh_sqlite_cache(self, make_proxy, tmp_path):
        import json as jsonlib

        db_path = tmp_path / "cache.db"
        legacy_path = tmp_path / "cache.json"
        legacy_path.write_text(jsonlib.dumps({
            "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
            "pending": {"5.6.7.8": {"due_time": 2000, "severity": 3,
                                     "categories": "15", "comment": "hacking"}},
            "retry_queue": {},
        }))

        p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
        cache = p.load_cache()

        assert cache["reports"] == {"1.2.3.4": {"time": 1000, "severity": 2}}
        entry = cache["pending"]["5.6.7.8"]
        assert entry["due_time"] == 2000
        assert entry["severity"] == 3
        assert entry["categories"] == "15"
        assert entry["comment"] == "hacking"
        # Legacy JSON predates created_at -- must fall back to "now"
        # rather than staying NULL/missing when migrated into SQLite.
        assert entry["created_at"] is not None

    def test_legacy_v1_0_0_flat_format_is_also_migrated(self, make_proxy, tmp_path):
        import json as jsonlib

        db_path = tmp_path / "cache.db"
        legacy_path = tmp_path / "cache.json"
        legacy_path.write_text(jsonlib.dumps({"1.2.3.4": {"time": 1000, "severity": 2}}))

        p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
        cache = p.load_cache()

        assert cache["reports"] == {"1.2.3.4": {"time": 1000, "severity": 2}}

    def test_old_file_is_renamed_not_deleted(self, make_proxy, tmp_path):
        import json as jsonlib

        db_path = tmp_path / "cache.db"
        legacy_path = tmp_path / "cache.json"
        legacy_path.write_text(jsonlib.dumps({"reports": {}, "pending": {}, "retry_queue": {}}))

        p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
        p.load_cache()

        assert not legacy_path.exists()
        assert (tmp_path / "cache.json.migrated").exists()

    def test_migration_runs_at_most_once(self, make_proxy, tmp_path, monkeypatch):
        import json as jsonlib

        db_path = tmp_path / "cache.db"
        legacy_path = tmp_path / "cache.json"
        legacy_path.write_text(jsonlib.dumps({
            "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
            "pending": {}, "retry_queue": {},
        }))

        p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
        p.load_cache()  # first call: migrates

        # Simulate someone dropping a *new* cache.json back in after the
        # fact (e.g. restoring an old backup by hand) — must NOT be
        # re-imported, since the sqlite db already exists and has its own
        # (possibly newer) history by now.
        legacy_path.write_text(jsonlib.dumps({
            "reports": {"9.9.9.9": {"time": 5000, "severity": 1}},
            "pending": {}, "retry_queue": {},
        }))

        cache = p.load_cache()
        assert "9.9.9.9" not in cache["reports"]
        assert "1.2.3.4" in cache["reports"]

    def test_sends_a_notification_about_the_migration(self, make_proxy, tmp_path, monkeypatch):
        import json as jsonlib

        db_path = tmp_path / "cache.db"
        legacy_path = tmp_path / "cache.json"
        legacy_path.write_text(jsonlib.dumps({"reports": {}, "pending": {}, "retry_queue": {}}))

        p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
        calls = []
        monkeypatch.setattr(p, "notify", lambda msg, priority="high": calls.append((msg, priority)))

        p.load_cache()

        assert len(calls) == 1
        assert calls[0][1] == "normal"
        assert "migrat" in calls[0][0].lower()

    def test_a_corrupt_legacy_file_does_not_block_startup(self, make_proxy, tmp_path):
        db_path = tmp_path / "cache.db"
        legacy_path = tmp_path / "cache.json"
        legacy_path.write_text("{not valid json")

        p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(db_path))
        cache = p.load_cache()  # must not raise

        assert cache == {"reports": {}, "pending": {}, "retry_queue": {}}

    def test_no_migration_when_no_legacy_file_exists(self, sqlite_proxy):
        # sqlite_proxy's tmp_path has no cache.json sitting next to it —
        # a completely fresh install, nothing to migrate.
        assert sqlite_proxy.load_cache() == {"reports": {}, "pending": {}, "retry_queue": {}}

    def test_no_migration_when_sqlite_cache_already_exists(self, sqlite_proxy, tmp_path):
        import json as jsonlib

        sqlite_proxy.save_cache({"reports": {"1.1.1.1": {"time": 1, "severity": 1}},
                                  "pending": {}, "retry_queue": {}})

        legacy_path = self._legacy_json_path(sqlite_proxy.CACHE_FILE)
        with open(legacy_path, "w") as f:
            jsonlib.dump({"reports": {"9.9.9.9": {"time": 2, "severity": 3}},
                          "pending": {}, "retry_queue": {}}, f)

        cache = sqlite_proxy.load_cache()
        assert "9.9.9.9" not in cache["reports"]
        assert "1.1.1.1" in cache["reports"]


def test_count_tracked_reports_matches_load_cache_length(sqlite_proxy):
    sqlite_proxy.save_cache({
        "reports": {"1.1.1.1": {"time": 1, "severity": 1}, "2.2.2.2": {"time": 2, "severity": 2}},
        "pending": {}, "retry_queue": {},
    })
    assert sqlite_proxy.count_tracked_reports() == 2
    assert sqlite_proxy.count_tracked_reports() == len(sqlite_proxy.load_cache()["reports"])


def test_count_tracked_reports_zero_on_empty_cache(sqlite_proxy):
    assert sqlite_proxy.count_tracked_reports() == 0


def test_health_endpoint_uses_count_not_full_load(running_server, monkeypatch):
    # Regression test: /health used to load_cache() the entire reports
    # table just to take len() of it. Confirms it now goes through the
    # lightweight COUNT(*) path instead.
    p, base_url = running_server(ABUSEIPDB_ENABLE_HEALTH="true")
    calls = {"load_cache": 0, "count": 0}

    real_load_cache = p.load_cache
    real_count = p.count_tracked_reports

    def spy_load_cache():
        calls["load_cache"] += 1
        return real_load_cache()

    def spy_count():
        calls["count"] += 1
        return real_count()

    p.load_cache = spy_load_cache
    p.count_tracked_reports = spy_count

    import urllib.request
    with urllib.request.urlopen(base_url + "/health", timeout=5) as resp:
        assert resp.status == 200

    assert calls["count"] == 1
    assert calls["load_cache"] == 0


# --- Single-row hot-path operations & periodic stale-report sweep ----------

def test_sqlite_get_report_returns_none_for_missing_ip(sqlite_proxy):
    assert sqlite_proxy._sqlite_get_report("1.2.3.4") is None


def test_sqlite_get_report_and_upsert_round_trip(sqlite_proxy):
    sqlite_proxy._sqlite_upsert_report("1.2.3.4", 1000, 2)
    assert sqlite_proxy._sqlite_get_report("1.2.3.4") == {"time": 1000, "severity": 2}


def test_sqlite_upsert_report_overwrites_existing_row(sqlite_proxy):
    sqlite_proxy._sqlite_upsert_report("1.2.3.4", 1000, 2)
    sqlite_proxy._sqlite_upsert_report("1.2.3.4", 2000, 3)
    assert sqlite_proxy._sqlite_get_report("1.2.3.4") == {"time": 2000, "severity": 3}


def test_sqlite_upsert_pending_and_delete(sqlite_proxy):
    sqlite_proxy._sqlite_upsert_pending("5.6.7.8", 2000, 3, "18", "x")
    cache = sqlite_proxy.load_cache()
    entry = cache["pending"]["5.6.7.8"]
    assert entry["due_time"] == 2000
    assert entry["severity"] == 3
    assert entry["categories"] == "18"
    assert entry["comment"] == "x"
    assert entry["created_at"] is not None
    sqlite_proxy._sqlite_delete_pending("5.6.7.8")
    assert "5.6.7.8" not in sqlite_proxy.load_cache()["pending"]


def test_sqlite_delete_pending_missing_ip_is_a_silent_no_op(sqlite_proxy):
    sqlite_proxy._sqlite_delete_pending("no.such.ip.here")  # must not raise


def test_sqlite_upsert_retry_and_delete(sqlite_proxy):
    sqlite_proxy._sqlite_upsert_retry("1.1.1.1", 3000, "15", "y", 2)
    cache = sqlite_proxy.load_cache()
    entry = cache["retry_queue"]["1.1.1.1"]
    assert entry["due_time"] == 3000
    assert entry["categories"] == "15"
    assert entry["comment"] == "y"
    assert entry["attempts"] == 2
    assert entry["created_at"] is not None
    sqlite_proxy._sqlite_delete_retry("1.1.1.1")
    assert "1.1.1.1" not in sqlite_proxy.load_cache()["retry_queue"]


def test_stale_report_sweep_removes_only_stale_rows(sqlite_proxy):
    now = int(sqlite_proxy.time.time())
    sqlite_proxy.save_cache({
        "reports": {
            "stale.ip": {"time": now - 90_000, "severity": 1},   # > 24h old
            "fresh.ip": {"time": now - 100, "severity": 1},      # recent
        },
        "pending": {}, "retry_queue": {},
    })
    sqlite_proxy._last_stale_report_sweep = 0.0  # force it to actually run

    sqlite_proxy._maybe_sweep_stale_reports()

    cache = sqlite_proxy.load_cache()
    assert "stale.ip" not in cache["reports"]
    assert "fresh.ip" in cache["reports"]


def test_stale_report_sweep_only_runs_once_per_interval(sqlite_proxy):
    now = int(sqlite_proxy.time.time())
    sqlite_proxy.save_cache({
        "reports": {"stale.ip": {"time": now - 90_000, "severity": 1}},
        "pending": {}, "retry_queue": {},
    })
    sqlite_proxy._last_stale_report_sweep = sqlite_proxy.time.time()  # "just ran"

    sqlite_proxy._maybe_sweep_stale_reports()

    # the sweep was skipped (still within the interval) — the stale row
    # is still there
    assert "stale.ip" in sqlite_proxy.load_cache()["reports"]


def test_process_alert_triggers_the_sweep_and_respects_its_interval(proxy, deferred_thread):
    now = int(proxy.time.time())
    proxy.save_cache({
        "reports": {"stale.ip": {"time": now - 90_000, "severity": 1}},
        "pending": {}, "retry_queue": {},
    })
    proxy._last_stale_report_sweep = 0.0

    proxy.process_alert("1.2.3.4", "15", "test", new_severity=1)

    assert "stale.ip" not in proxy.load_cache()["reports"]


def test_concurrent_sweep_calls_only_claim_the_interval_once(sqlite_proxy):
    """
    Regression test for moving the sweep's DELETE outside the main `lock`
    (so it no longer blocks concurrent per-ip alert processing): the
    "is a sweep due, and if so, claim it" check now runs under its own
    dedicated `_sweep_lock` rather than the caller already holding
    `lock` for it. Confirms many genuinely concurrent callers still only
    let exactly one of them see "yes, it's due" -- not each of them
    racing the read-then-write of `_last_stale_report_sweep` and all
    deciding it's their turn.
    """
    sqlite_proxy._last_stale_report_sweep = 0.0
    claims = []
    claims_lock = threading.Lock()

    real_delete = sqlite_proxy._sqlite_connect

    def counting_connect(*args, **kwargs):
        # Runs unlocked (by design) -- just observing here, not
        # synchronizing, so a race would actually show up as >1 claim.
        with claims_lock:
            claims.append(1)
        return real_delete(*args, **kwargs)

    sqlite_proxy._sqlite_connect = counting_connect
    try:
        with ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda _: sqlite_proxy._maybe_sweep_stale_reports(), range(20)))
    finally:
        sqlite_proxy._sqlite_connect = real_delete

    assert len(claims) == 1
