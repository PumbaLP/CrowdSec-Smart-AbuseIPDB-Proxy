"""
Tests for four opt-in additions, all off by default:

- Per-category report windows (ABUSEIPDB_REPORT_WINDOW_CATEGORIES)
- Quota reservation per severity tier (ABUSEIPDB_QUOTA_RESERVE_MEDIUM/_HIGH)
- Local-port access control (ABUSEIPDB_ALLOWED_SOURCE_IPS / _SHARED_SECRET)
- AbuseIPDB whitelist pre-check (ABUSEIPDB_SKIP_WHITELISTED)
"""
import json
import urllib.error

import pytest


# --- Per-category report windows -------------------------------------------

def test_no_category_windows_falls_back_to_severity_window(proxy):
    assert proxy.get_report_window(2, "22") == proxy.REPORT_WINDOWS[2]


def test_category_override_wins_over_severity_window(make_proxy):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_CATEGORIES="16=1800,20=3600")
    assert p.get_report_window(3, "16") == 1800
    assert p.get_report_window(3, "20") == 3600
    # a category with no override still falls back to the severity window
    assert p.get_report_window(3, "15") == p.REPORT_WINDOWS[3]


def test_multiple_overridden_categories_use_the_smallest_window(make_proxy):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_CATEGORIES="16=1800,20=3600")
    assert p.get_report_window(3, "16,20") == 1800


def test_malformed_category_windows_entry_is_skipped_not_fatal(make_proxy):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_CATEGORIES="not-valid,16=1800")
    assert p.get_report_window(3, "16") == 1800


def test_escalation_uses_category_window_end_to_end(make_proxy, fake_timer, deferred_thread):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_CATEGORIES="16=1800", ABUSEIPDB_REPORT_WINDOW_HIGH="905")
    p.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    # escalate with an overridden category — 1800s window means this
    # should be *delayed*, not sent immediately, even though the default
    # severity-3 window (905s) would already have elapsed... but nothing
    # has elapsed at all here (t=0), so either window would delay it.
    # The real assertion is on *which* window got applied:
    p.process_alert("1.2.3.4", "16", "sql injection", new_severity=3)
    assert len(fake_timer.instances) == 1
    assert fake_timer.instances[0].interval == 1800


# --- Quota reservation -------------------------------------------------------

def test_reservation_disabled_by_default(proxy):
    proxy.quota_state["remaining"] = 0
    assert proxy.quota_reserved_for(1) is False
    assert proxy.quota_reserved_for(3) is False


def test_no_reservation_before_quota_is_known(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="100")
    assert p.quota_state["remaining"] is None
    assert p.quota_reserved_for(1) is False


def test_low_severity_blocked_once_high_reserve_threshold_hit(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="50")
    p.quota_state["remaining"] = 50
    assert p.quota_reserved_for(1) is True
    assert p.quota_reserved_for(2) is True
    assert p.quota_reserved_for(3) is False  # severity 3 is never reserved against


def test_medium_reserve_only_blocks_severity_1(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_MEDIUM="50")
    p.quota_state["remaining"] = 50
    assert p.quota_reserved_for(1) is True
    assert p.quota_reserved_for(2) is False
    assert p.quota_reserved_for(3) is False


def test_reservation_lifts_once_remaining_is_above_threshold(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="50")
    p.quota_state["remaining"] = 51
    assert p.quota_reserved_for(1) is False


def test_new_low_severity_ip_is_held_back_when_reserved(make_proxy, deferred_thread):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="10")
    p.quota_state["remaining"] = 10
    p.process_alert("1.2.3.4", "14", "port scan", new_severity=1)

    assert p.metrics["reports_quota_reserved_total"] == 1
    assert "1.2.3.4" not in p.load_cache()["reports"]


def test_high_severity_still_goes_through_when_reserved_for_it(make_proxy, deferred_thread):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="10")
    p.quota_state["remaining"] = 10
    p.process_alert("1.2.3.4", "16", "sql injection", new_severity=3)

    assert p.metrics["reports_quota_reserved_total"] == 0
    assert "1.2.3.4" in p.load_cache()["reports"]


def test_pending_escalation_is_dropped_if_quota_becomes_reserved_before_it_fires(
    make_proxy, fake_timer, deferred_thread
):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="10")
    p.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    p.process_alert("1.2.3.4", "18", "brute-force", new_severity=2)  # scheduled, window not elapsed
    assert len(fake_timer.instances) == 1

    # quota tightens while the escalation is still pending
    p.quota_state["remaining"] = 10
    fake_timer.instances[0].fire()

    assert p.metrics["reports_quota_reserved_total"] == 1
    assert "1.2.3.4" not in p.load_cache()["pending"]


# --- Local-port access control ----------------------------------------------

def test_no_allowlist_configured_allows_any_source(proxy):
    assert proxy.is_source_ip_allowed("203.0.113.5") is True


def test_allowlist_permits_only_listed_sources(make_proxy):
    p = make_proxy(ABUSEIPDB_ALLOWED_SOURCE_IPS="127.0.0.1,10.0.0.0/24")
    assert p.is_source_ip_allowed("127.0.0.1") is True
    assert p.is_source_ip_allowed("10.0.0.5") is True
    assert p.is_source_ip_allowed("203.0.113.5") is False


def test_malformed_allowlist_entry_is_skipped_not_fatal(make_proxy):
    p = make_proxy(ABUSEIPDB_ALLOWED_SOURCE_IPS="not-a-cidr,127.0.0.1")
    assert p.is_source_ip_allowed("127.0.0.1") is True


def test_no_shared_secret_configured_accepts_anything(proxy):
    assert proxy.is_shared_secret_valid(None) is True
    assert proxy.is_shared_secret_valid("whatever") is True


def test_shared_secret_must_match_exactly(make_proxy):
    p = make_proxy(ABUSEIPDB_SHARED_SECRET="s3cret")
    assert p.is_shared_secret_valid("s3cret") is True
    assert p.is_shared_secret_valid("wrong") is False
    assert p.is_shared_secret_valid(None) is False


# --- AbuseIPDB whitelist pre-check ------------------------------------------

def test_whitelist_check_disabled_by_default(proxy):
    assert proxy.is_whitelisted("1.2.3.4") is False


def test_whitelist_check_disabled_in_dry_run_even_if_enabled(make_proxy):
    # ABUSEIPDB_DRY_RUN=true is the make_proxy default; explicitly set
    # SKIP_WHITELISTED to confirm dry-run still short-circuits it before
    # any network call would happen.
    p = make_proxy(ABUSEIPDB_SKIP_WHITELISTED="true")
    assert p.is_whitelisted("1.2.3.4") is False


def test_whitelisted_ip_is_detected_and_cached(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_SKIP_WHITELISTED="true", ABUSEIPDB_DRY_RUN="false")
    calls = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload
        def read(self):
            return json.dumps(self._payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=10):
        calls.append(req.full_url)
        return FakeResponse({"data": {"isWhitelisted": True}})

    monkeypatch.setattr(p.urllib.request, "urlopen", fake_urlopen)

    assert p.is_whitelisted("1.1.1.1") is True
    assert p.is_whitelisted("1.1.1.1") is True  # served from cache
    assert len(calls) == 1  # only one real /v2/check call was made


def test_whitelist_check_failure_fails_open(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_SKIP_WHITELISTED="true", ABUSEIPDB_DRY_RUN="false")

    def fake_urlopen(req, timeout=10):
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(p.urllib.request, "urlopen", fake_urlopen)

    # a broken /v2/check must never block a legitimate report
    assert p.is_whitelisted("1.1.1.1") is False


def test_whitelist_cache_evicts_expired_entries_on_write(make_proxy, monkeypatch):
    # Regression test: _whitelist_cache used to grow forever (one entry
    # per unique IP ever checked, never evicted) — a slow memory leak on
    # any long-running instance with SKIP_WHITELISTED on and a lot of
    # distinct source IPs (a honeypot-style setup being the realistic
    # case). Entries older than the TTL should get swept out as new
    # checks come in, not pile up indefinitely.
    p = make_proxy(ABUSEIPDB_SKIP_WHITELISTED="true", ABUSEIPDB_DRY_RUN="false",
                    ABUSEIPDB_WHITELIST_CACHE_TTL="100")

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload
        def read(self):
            return json.dumps(self._payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=10):
        return FakeResponse({"data": {"isWhitelisted": False}})

    monkeypatch.setattr(p.urllib.request, "urlopen", fake_urlopen)

    p.is_whitelisted("1.1.1.1")
    assert "1.1.1.1" in p._whitelist_cache

    # simulate the first entry having aged past the TTL, then check a
    # brand-new IP — that write should sweep the stale one out
    ip, (whitelisted, checked_at) = "1.1.1.1", p._whitelist_cache["1.1.1.1"]
    p._whitelist_cache["1.1.1.1"] = (whitelisted, checked_at - 200)

    p.is_whitelisted("2.2.2.2")

    assert "1.1.1.1" not in p._whitelist_cache
    assert "2.2.2.2" in p._whitelist_cache
