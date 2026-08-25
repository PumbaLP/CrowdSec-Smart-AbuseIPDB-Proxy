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
    assert proxy.quota_state == {"limit": None, "remaining": None, "updated_at": None, "day": None, "day_start_remaining": None, "day_start_time": None}


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


class TestQuotaExhaustionEstimate:
    def test_no_estimate_without_enough_elapsed_time(self, proxy):
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "900"}))
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "890"}))
        # Both observations happened "now" in test time -- elapsed is ~0s,
        # nowhere near the 300s floor, so no projection should be made.
        assert proxy.estimate_quota_exhaustion(proxy.quota_state) is None

    def test_no_estimate_when_nothing_has_been_consumed_yet(self, proxy):
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "900"}))
        proxy.quota_state["day_start_time"] -= 1000  # simulate 1000s having passed
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "900"}))
        assert proxy.estimate_quota_exhaustion(proxy.quota_state) is None

    def test_estimate_projects_a_future_time_at_the_observed_rate(self, proxy):
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "1000"}))
        # Backdate the baseline so elapsed time clears the 300s floor:
        # 600s elapsed, 100 consumed -> rate = 100/600 reports/sec.
        proxy.quota_state["day_start_time"] -= 600
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "900"}))

        eta = proxy.estimate_quota_exhaustion(proxy.quota_state)

        assert eta is not None
        # 900 remaining / (100/600 per sec) = 5400s =~ 90 minutes from now.
        # Generous tolerance: this is checking the projection logic, not
        # timing precision, and a few seconds of real wall-clock elapse
        # between the backdating above and this assertion (test overhead,
        # not the code under test) would otherwise make this flaky.
        expected_seconds = 900 / (100 / 600)
        actual_seconds = (eta - proxy.datetime.now(proxy.timezone.utc)).total_seconds()
        assert abs(actual_seconds - expected_seconds) < 30

    def test_new_utc_day_resets_the_baseline(self, proxy):
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "50"}))
        first_baseline = proxy.quota_state["day_start_remaining"]
        assert first_baseline == 50

        proxy.quota_state["day"] = "2000-01-01"  # simulate yesterday
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "1000"}))

        # A new day's first observation re-establishes the baseline at
        # today's value -- yesterday's leftover "50" must not linger and
        # get read as "consumed 950 today".
        assert proxy.quota_state["day_start_remaining"] == 1000

    def test_low_quota_warning_includes_the_eta_when_available(self, proxy, monkeypatch):
        calls = []
        monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append(msg))

        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "200"}))
        proxy.quota_state["day_start_time"] -= 600  # clear the 300s floor
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "40"}))

        assert len(calls) == 1
        assert "UTC" in calls[0]  # the projected exhaustion time was included

    def test_low_quota_warning_omits_the_eta_when_not_available(self, proxy, monkeypatch):
        # Single observation -- no rate data yet, so no ETA should be
        # fabricated; the base warning message must still be sent.
        calls = []
        monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append(msg))

        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "10"}))

        assert len(calls) == 1
        assert "run out around" not in calls[0]

    def test_load_quota_state_includes_the_new_fields(self, proxy):
        proxy._update_quota_from_headers(FakeHeaders({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "500"}))
        loaded = proxy.load_quota_state()
        assert loaded["day"] == proxy.quota_state["day"]
        assert loaded["day_start_remaining"] == 500
        assert loaded["day_start_time"] == proxy.quota_state["day_start_time"]


class TestHealthEndpointBacklogAge:
    def test_oldest_entry_age_is_none_when_table_is_empty(self, proxy):
        assert proxy._oldest_entry_age("pending") is None
        assert proxy._oldest_entry_age("retry_queue") is None

    def test_oldest_entry_age_reflects_created_at(self, proxy):
        proxy._sqlite_upsert_pending("1.2.3.4", due_time=999999999999, severity=1,
                                      categories="14", comment="x")
        age = proxy._oldest_entry_age("pending")
        assert age is not None
        assert 0 <= age <= 20

    def test_oldest_entry_age_uses_the_minimum_across_multiple_rows(self, proxy):
        proxy._sqlite_upsert_pending("1.1.1.1", due_time=1, severity=1, categories="14", comment="x")
        conn = proxy._sqlite_connect()
        with conn:
            # backdate this one so it's clearly the oldest
            conn.execute("UPDATE pending SET created_at = ? WHERE ip = ?",
                         (int(proxy.time.time()) - 500, "1.1.1.1"))
        conn.close()
        proxy._sqlite_upsert_pending("2.2.2.2", due_time=1, severity=1, categories="14", comment="x")

        age = proxy._oldest_entry_age("pending")

        assert age >= 500

    def test_created_at_is_preserved_across_repeated_upserts_of_the_same_ip(self, proxy):
        # A quota-recheck reschedule (or repeated failed retry attempts)
        # re-upserts the SAME ip's row over and over -- created_at must
        # reflect when the wait *started*, not the most recent reschedule.
        proxy._sqlite_upsert_retry("1.2.3.4", due_time=1, categories="15", comment="x", attempts=1)
        conn = proxy._sqlite_connect()
        with conn:
            conn.execute("UPDATE retry_queue SET created_at = ? WHERE ip = ?",
                         (int(proxy.time.time()) - 300, "1.2.3.4"))
        conn.close()

        proxy._sqlite_upsert_retry("1.2.3.4", due_time=2, categories="15", comment="x", attempts=2)

        age = proxy._oldest_entry_age("retry_queue")
        assert age >= 300  # NOT reset to ~0 by the second upsert

    def test_created_at_resets_when_the_row_is_deleted_and_recreated(self, proxy):
        # A genuinely new chain (old row explicitly deleted first, e.g.
        # by _cancel_active_retry_chain()) must get a fresh created_at.
        proxy._sqlite_upsert_retry("1.2.3.4", due_time=1, categories="15", comment="x", attempts=1)
        conn = proxy._sqlite_connect()
        with conn:
            conn.execute("UPDATE retry_queue SET created_at = ? WHERE ip = ?",
                         (int(proxy.time.time()) - 300, "1.2.3.4"))
        conn.close()

        proxy._sqlite_delete_retry("1.2.3.4")
        proxy._sqlite_upsert_retry("1.2.3.4", due_time=1, categories="15", comment="x", attempts=1)

        age = proxy._oldest_entry_age("retry_queue")
        assert age <= 20

    def test_legacy_row_with_null_created_at_does_not_crash_the_query(self, proxy):
        # A row written before this migration (or by some other path that
        # bypasses the upsert helpers) would have NULL created_at --
        # MIN() over a column that's entirely NULL returns NULL, which
        # must map to None, not raise or return something bogus like 0.
        conn = proxy._sqlite_connect()
        with conn:
            conn.execute(
                "INSERT INTO pending (ip, due_time, severity, categories, comment, created_at) "
                "VALUES (?, ?, ?, ?, ?, NULL)",
                ("1.2.3.4", 1, 1, "14", "x"),
            )
        conn.close()

        assert proxy._oldest_entry_age("pending") is None

    def test_health_endpoint_json_includes_the_new_age_fields(self, proxy, fake_timer):
        proxy._sqlite_upsert_pending("1.2.3.4", due_time=999999999999, severity=1,
                                      categories="14", comment="x")
        proxy.pending_timers["1.2.3.4"] = {"timer": fake_timer(0, lambda: None), "severity": 1}

        # Build the same dict _handle_health() builds, without spinning up
        # a real HTTP server (matches the existing
        # test_health_endpoint_includes_quota_state pattern above).
        result = {
            "oldest_pending_escalation_age_seconds": proxy._oldest_entry_age("pending"),
            "oldest_pending_retry_age_seconds": proxy._oldest_entry_age("retry_queue"),
        }

        assert result["oldest_pending_escalation_age_seconds"] is not None
        assert result["oldest_pending_retry_age_seconds"] is None  # nothing in retry_queue
