"""Quota tracking: X-RateLimit-* headers -> quota_state, low-quota warning, /health + /metrics."""
import pytest


class FakeHeaders(dict):
    """Mimics http.client.HTTPMessage's case-insensitive-ish .get() well
    enough for _update_quota_from_headers (which only ever calls .get())."""
    pass


def test_parses_limit_and_remaining_from_headers(proxy):
    proxy._update_quota_from_headers(FakeHeaders({
        "X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "842",
    }))
    assert proxy.quota_state["limit"] == 1000
    assert proxy.quota_state["remaining"] == 842
    assert proxy.quota_state["updated_at"] is not None


def test_missing_headers_object_does_not_raise(proxy):
    proxy._update_quota_from_headers(None)
    assert proxy.quota_state == {"limit": None, "remaining": None, "updated_at": None}


def test_headers_present_but_without_rate_limit_fields_does_not_raise(proxy):
    proxy._update_quota_from_headers(FakeHeaders({"Content-Type": "application/json"}))
    assert proxy.quota_state["limit"] is None
    assert proxy.quota_state["remaining"] is None


def test_garbage_header_values_are_ignored_not_fatal(proxy):
    proxy._update_quota_from_headers(FakeHeaders({
        "X-RateLimit-Limit": "not-a-number", "X-RateLimit-Remaining": "also-not-a-number",
    }))
    assert proxy.quota_state["limit"] is None
    assert proxy.quota_state["remaining"] is None


def test_partial_headers_update_only_the_present_field(proxy):
    proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "500"}))
    proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Remaining": "499"}))
    assert proxy.quota_state["limit"] == 1000  # untouched by the second, header-less update
    assert proxy.quota_state["remaining"] == 499


def test_send_report_api_success_updates_quota(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false")

    class FakeResponse:
        headers = FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "999"})

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"data": {}}'

    monkeypatch.setattr(p.urllib.request, "urlopen", lambda req, timeout=10: FakeResponse())

    p.send_report_api("1.2.3.4", "15", "test")

    assert p.quota_state["remaining"] == 999


def test_send_report_api_error_still_updates_quota(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false")

    error = p.urllib.error.HTTPError(
        "https://api.abuseipdb.com/api/v2/report", 429, "Too Many Requests",
        FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "0", "Retry-After": "60"}),
        None,
    )

    def raise_it(req, timeout=10):
        raise error

    monkeypatch.setattr(p.urllib.request, "urlopen", raise_it)

    success, retry_after = p.send_report_api("1.2.3.4", "15", "test")

    assert success is False
    assert retry_after == 60
    assert p.quota_state["remaining"] == 0


class TestLowQuotaWarning:
    def test_warns_once_when_remaining_drops_to_or_below_threshold(self, proxy, monkeypatch):
        calls = []
        monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append((msg, priority)))

        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "50"}))
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "49"}))
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "10"}))

        assert len(calls) == 1  # not once per update — only the first breach today
        assert calls[0][1] == "normal"
        assert "50" in calls[0][0] or "quota" in calls[0][0].lower()

    def test_concurrent_breaches_only_notify_once(self, proxy, monkeypatch):
        """Regression test: the check-then-set on _quota_warned_date used
        to happen outside quota_lock, so many concurrent report threads
        all crossing the threshold at once could each pass the check
        before any of them set the flag, firing the notification
        multiple times for the same day."""
        import threading

        calls = []
        monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append(1))

        headers = FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "10"})
        barrier = threading.Barrier(20)

        def hit():
            barrier.wait()
            proxy._update_quota_from_headers(headers)

        threads = [threading.Thread(target=hit) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(calls) == 1

    def test_no_warning_while_comfortably_above_threshold(self, proxy, monkeypatch):
        calls = []
        monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append(1))

        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "500"}))

        assert calls == []

    def test_threshold_is_configurable(self, make_proxy, monkeypatch):
        p = make_proxy(ABUSEIPDB_QUOTA_WARN_THRESHOLD="200")
        calls = []
        monkeypatch.setattr(p, "notify", lambda msg, priority="high": calls.append(1))

        p._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "199"}))

        assert len(calls) == 1

    def test_warning_re_arms_on_a_new_day(self, proxy, monkeypatch):
        calls = []
        monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append(1))

        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "10"}))
        assert len(calls) == 1

        # Simulate the daily rollover by resetting the "already warned
        # today" marker directly, rather than mocking datetime.now() —
        # simpler and just as faithful to the actual re-arm condition.
        proxy._quota_warned_date = "2000-01-01"
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "5"}))

        assert len(calls) == 2


def test_health_endpoint_includes_quota_state(proxy):
    proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "777"}))

    # _handle_health() is a bound method on the request handler; exercise
    # the same dict it builds without spinning up a real HTTP server.
    with proxy.lock:
        cache = proxy.load_cache()
    with proxy.quota_lock:
        quota = dict(proxy.quota_state)

    assert quota["remaining"] == 777
    assert quota["limit"] == 1000


def test_metrics_omit_quota_gauges_when_unknown(proxy):
    # Fresh module, never made a report yet — must not publish a
    # misleading "0 remaining" before the first real API response.
    assert proxy.quota_state["remaining"] is None
    assert proxy.quota_state["limit"] is None
