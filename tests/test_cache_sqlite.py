"""load_cache() / save_cache() with ABUSEIPDB_CACHE_BACKEND=sqlite."""
import sqlite3

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
    assert sqlite_proxy.load_cache() == cache


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


def test_switching_backends_in_different_directories_does_not_share_state(make_proxy, tmp_path):
    # Genuinely separate directories — no legacy cache.json for the
    # SQLite backend to find, so no migration should kick in and the two
    # caches must stay fully independent.
    json_dir = tmp_path / "json"
    json_dir.mkdir()
    sqlite_dir = tmp_path / "sqlite"
    sqlite_dir.mkdir()

    json_proxy = make_proxy(
        ABUSEIPDB_CACHE_BACKEND="json",
        ABUSEIPDB_CACHE_FILE=str(json_dir / "cache.json"),
    )
    json_proxy.save_cache({"reports": {"1.2.3.4": {"time": 1, "severity": 1}},
                            "pending": {}, "retry_queue": {}})

    sqlite_proxy = make_proxy(
        ABUSEIPDB_CACHE_BACKEND="sqlite",
        ABUSEIPDB_CACHE_FILE=str(sqlite_dir / "cache.db"),
    )
    assert sqlite_proxy.load_cache() == {"reports": {}, "pending": {}, "retry_queue": {}}


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
        assert cache["pending"] == {"5.6.7.8": {"due_time": 2000, "severity": 3,
                                                  "categories": "15", "comment": "hacking"}}

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
