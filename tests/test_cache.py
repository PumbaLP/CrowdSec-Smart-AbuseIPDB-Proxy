"""load_cache() / save_cache(): persistence and legacy-format upgrades."""
import json


def test_missing_cache_file_returns_empty_structure(proxy):
    cache = proxy.load_cache()
    assert cache == {"reports": {}, "pending": {}, "retry_queue": {}}


def test_save_then_load_round_trips(proxy):
    cache = {
        "reports": {"1.2.3.4": {"time": 1000, "severity": 2}},
        "pending": {},
        "retry_queue": {},
    }
    proxy.save_cache(cache)
    assert proxy.load_cache() == cache


def test_corrupt_json_falls_back_to_empty_structure(proxy):
    with open(proxy.CACHE_FILE, "w") as f:
        f.write("{not valid json")
    cache = proxy.load_cache()
    assert cache == {"reports": {}, "pending": {}, "retry_queue": {}}



def test_save_cache_is_atomic_no_tmp_file_left_behind(proxy):
    proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    import os
    assert not os.path.exists(proxy.CACHE_FILE + ".tmp")
    assert os.path.exists(proxy.CACHE_FILE)


def test_save_cache_failure_triggers_one_high_priority_notification(proxy, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append((msg, priority)))
    # Put a *file* where the cache directory needs to be, so
    # ensure_cache_dir()'s os.makedirs() reliably fails (even running as
    # root, which would otherwise happily create any nested directory).
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    monkeypatch.setattr(proxy, "CACHE_FILE", str(blocker / "cache.json"))

    proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})

    assert len(calls) == 1  # only alerts once, not on every failed write
    assert calls[0][1] == "high"


def test_save_cache_recovers_after_a_failure(proxy, monkeypatch, tmp_path):
    monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": None)
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    monkeypatch.setattr(proxy, "CACHE_FILE", str(blocker / "cache.json"))
    proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    assert proxy._cache_write_failing is True

    monkeypatch.setattr(proxy, "CACHE_FILE", str(tmp_path / "cache.json"))
    proxy.save_cache({"reports": {}, "pending": {}, "retry_queue": {}})
    assert proxy._cache_write_failing is False
