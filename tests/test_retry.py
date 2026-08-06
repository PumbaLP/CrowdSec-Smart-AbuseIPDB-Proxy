"""send_with_retry() / send_report_api(): retry, backoff, give-up alert."""


def test_dry_run_never_calls_the_real_api(proxy, monkeypatch):
    called = []
    monkeypatch.setattr(proxy.urllib.request, "urlopen", lambda *a, **k: called.append(1))
    success, retry_after = proxy.send_report_api("1.2.3.4", "15", "test")
    assert success is True
    assert retry_after is None
    assert called == []


def test_successful_report_increments_metric_and_clears_retry_queue(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (True, None))
    proxy.save_cache({"reports": {}, "pending": {},
                       "retry_queue": {"1.2.3.4": {"due_time": 0, "categories": "15",
                                                    "comment": "x", "attempts": 1}}})

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=2)

    assert proxy.metrics["reports_sent_total"] == 1
    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]
    assert "1.2.3.4" not in proxy.retry_timers


def test_failed_report_is_queued_for_retry_with_default_delay(proxy, monkeypatch, fake_timer):
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=1)

    entry = proxy.load_cache()["retry_queue"]["1.2.3.4"]
    assert entry["attempts"] == 1
    assert "1.2.3.4" in proxy.retry_timers
    assert fake_timer.instances[0].interval == proxy.RETRY_DELAY


def test_429_retry_after_header_overrides_default_delay(proxy, monkeypatch, fake_timer):
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, 120))

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=1)

    assert fake_timer.instances[0].interval == 120


def test_gives_up_after_max_retries_and_notifies_once(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    calls = []
    monkeypatch.setattr(proxy, "notify", lambda msg, priority="high": calls.append((msg, priority)))

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=proxy.MAX_RETRIES)

    assert proxy.metrics["reports_failed_total"] == 1
    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]
    assert len(calls) == 1
    assert calls[0][1] == "high"


def test_retry_chain_actually_advances_the_attempt_counter(proxy, monkeypatch, fake_timer):
    # Fails twice, then succeeds on the 3rd attempt — exercises the full
    # chain via fake_timer.fire() instead of asserting on a single call.
    attempts = {"n": 0}

    def flaky(ip, cats, comment):
        attempts["n"] += 1
        return (attempts["n"] >= 3, None)

    monkeypatch.setattr(proxy, "send_report_api", flaky)

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=1)
    assert attempts["n"] == 1
    fake_timer.instances[0].fire()  # attempt 2, still fails
    assert attempts["n"] == 2
    fake_timer.instances[1].fire()  # attempt 3, succeeds
    assert attempts["n"] == 3

    assert proxy.metrics["reports_sent_total"] == 1
    assert proxy.metrics["reports_failed_total"] == 0
    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]
