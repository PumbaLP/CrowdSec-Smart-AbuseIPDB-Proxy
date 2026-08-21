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
    assert entry["attempts"] == 2
    assert "1.2.3.4" in proxy.retry_timers
    assert fake_timer.instances[0].interval == proxy.RETRY_DELAY


def test_resumed_retry_chain_still_clears_the_reports_entry_on_giving_up(
    proxy, monkeypatch, fake_timer
):
    # A retry chain that was already in progress before a restart must
    # behave identically to a fresh one once resumed: if it goes on to
    # exhaust MAX_RETRIES, the stale "reports" entry must still be
    # cleared, not left behind because report_time got lost across the
    # restart boundary.
    report_time = 1000
    proxy.save_cache({
        "reports": {"1.2.3.4": {"time": report_time, "severity": 1}},
        "pending": {},
        "retry_queue": {"1.2.3.4": {"due_time": 0, "categories": "15", "comment": "test",
                                     "attempts": proxy.MAX_RETRIES}},
    })

    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    proxy.resume_state_from_cache()
    fake_timer.instances[0].fire()

    assert "1.2.3.4" not in proxy.load_cache()["reports"]
    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]


def test_resuming_a_retry_does_not_repeat_the_failed_attempt(proxy, monkeypatch, fake_timer):
    # attempt=1 fails -> persisted "attempts" must be 2 (the *next* attempt
    # number), so a restart-triggered resume doesn't replay attempt 1 again.
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=1)
    persisted = proxy.load_cache()["retry_queue"]["1.2.3.4"]["attempts"]

    proxy.retry_timers.clear()
    fake_timer.instances.clear()
    calls = []
    monkeypatch.setattr(proxy, "send_report_api",
                         lambda ip, cats, comment: (calls.append(1), (False, None))[1])

    proxy.resume_state_from_cache()
    fake_timer.instances[0].fire()

    # The resumed call must have used attempt=2 (persisted value), not
    # attempt=1 again -- verified by checking it re-persists attempts=3.
    assert proxy.load_cache()["retry_queue"]["1.2.3.4"]["attempts"] == persisted + 1


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


def test_giving_up_removes_the_reports_entry_so_future_alerts_are_not_blocked(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    now = 1000
    proxy.save_cache({"reports": {"1.2.3.4": {"time": now, "severity": 1}},
                       "pending": {}, "retry_queue": {}})

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=proxy.MAX_RETRIES, report_time=now)

    assert "1.2.3.4" not in proxy.load_cache()["reports"]


def test_giving_up_does_not_delete_a_fresher_entry_from_a_newer_escalation(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    old_time = 1000
    new_time = 2000
    # By the time the old retry chain gives up, a newer escalation has
    # already overwritten the "reports" row with a fresher timestamp.
    proxy.save_cache({"reports": {"1.2.3.4": {"time": new_time, "severity": 2}},
                       "pending": {}, "retry_queue": {}})

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=proxy.MAX_RETRIES, report_time=old_time)

    entry = proxy.load_cache()["reports"]["1.2.3.4"]
    assert entry["time"] == new_time


def test_giving_up_with_no_report_time_still_clears_the_retry_queue(proxy, monkeypatch):
    # Callers that don't (yet) track report_time (report_time=None, the
    # default) must not crash and must still clear the retry queue -- they
    # just skip the "reports" cleanup step.
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    proxy.save_cache({"reports": {"1.2.3.4": {"time": 1000, "severity": 1}},
                       "pending": {}, "retry_queue": {"1.2.3.4": {"due_time": 0, "categories": "15",
                                                                   "comment": "x", "attempts": proxy.MAX_RETRIES}}})

    proxy.send_with_retry("1.2.3.4", "15", "test", attempt=proxy.MAX_RETRIES)

    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]
    assert "1.2.3.4" in proxy.load_cache()["reports"]


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


# --- Concurrent retry chain collisions (single-key SQLite persistence) ------

def test_cancel_active_retry_chain_cancels_timer_and_clears_persisted_row(proxy, fake_timer):
    proxy.save_cache({"reports": {}, "pending": {},
                       "retry_queue": {"1.2.3.4": {"due_time": 0, "categories": "15",
                                                    "comment": "x", "attempts": 2}}})
    timer = fake_timer(0, lambda: None)
    proxy.retry_timers["1.2.3.4"] = timer

    proxy._cancel_active_retry_chain("1.2.3.4")

    assert timer.cancelled is True
    assert "1.2.3.4" not in proxy.retry_timers
    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]


def test_cancel_active_retry_chain_is_a_noop_when_nothing_is_active(proxy):
    # Must not raise even if there's no timer and no persisted row for the ip.
    proxy._cancel_active_retry_chain("9.9.9.9")
    assert "9.9.9.9" not in proxy.retry_timers


def test_escalation_cancels_a_still_active_retry_chain_for_the_same_ip(
    make_proxy, fake_timer, deferred_thread
):
    # Report window forced to 0 so the escalation below fires immediately
    # instead of being scheduled as a pending timer.
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW="0")

    # First alert: the initial report attempt fails, leaving an active
    # retry chain (a real threading.Timer-equivalent) queued for this ip.
    p.send_report_api = lambda ip, cats, comment: (False, None)
    p.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    deferred_thread.run_all()

    assert "1.2.3.4" in p.retry_timers
    assert "1.2.3.4" in p.load_cache()["retry_queue"]
    old_timer = p.retry_timers["1.2.3.4"]

    # Second alert for the same ip, now a higher severity: must cancel the
    # still-active retry chain from the first attempt before starting its
    # own, rather than letting both chains persist to the same db row.
    p.send_report_api = lambda ip, cats, comment: (False, None)
    p.process_alert("1.2.3.4", "18", "brute-force", new_severity=2)
    deferred_thread.run_all()

    assert old_timer.cancelled is True
    entry = p.load_cache()["retry_queue"]["1.2.3.4"]
    # Only the second chain's write should be visible -- attempt 1 failed
    # and persisted "attempts": 2 for its *own* next try.
    assert entry["comment"] == "brute-force"
    assert entry["attempts"] == 2


def test_due_escalation_cancels_a_still_active_retry_chain_for_the_same_ip(
    make_proxy, fake_timer, deferred_thread
):
    # Covers the third send_with_retry call site: _finalize_pending(),
    # reached when a scheduled (delayed) escalation becomes due while an
    # earlier report for the same ip is still mid-retry.
    p = make_proxy()

    p.send_report_api = lambda ip, cats, comment: (False, None)
    p.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    deferred_thread.run_all()
    assert "1.2.3.4" in p.retry_timers
    old_timer = p.retry_timers["1.2.3.4"]

    # Escalation for the same ip arrives before the report window elapses
    # -> scheduled as a pending timer (default window is > 0). instances[0]
    # is the retry backoff timer from the failed report above; the new
    # pending-escalation timer is instances[1].
    p.process_alert("1.2.3.4", "18", "brute-force", new_severity=2)
    assert len(fake_timer.instances) == 2
    pending_timer = fake_timer.instances[1]

    # The pending escalation becomes due while the original retry chain is
    # still active.
    p.send_report_api = lambda ip, cats, comment: (False, None)
    pending_timer.fire()
    deferred_thread.run_all()

    assert old_timer.cancelled is True
    entry = p.load_cache()["retry_queue"]["1.2.3.4"]
    assert entry["comment"] == "brute-force"


# --- Orphaned pending/retry rows (e.g. written by a short-lived --reconcile
# process, whose own in-memory timer dies with it) getting periodically
# re-armed by the long-running service ---------------------------------

def test_reap_arms_an_orphaned_retry_row_with_no_live_timer(proxy, fake_timer):
    # Simulates exactly what a --reconcile CLI invocation leaves behind:
    # a persisted retry_queue row (and its matching "reports" row) with
    # no corresponding entry in this process's retry_timers, because it
    # was written by a different, now-dead process.
    proxy.save_cache({
        "reports": {"1.2.3.4": {"time": 1000, "severity": 1}},
        "pending": {},
        "retry_queue": {"1.2.3.4": {"due_time": 999999999999, "categories": "15",
                                     "comment": "test", "attempts": 2}},
    })
    assert "1.2.3.4" not in proxy.retry_timers

    proxy._reap_orphaned_timers()

    assert "1.2.3.4" in proxy.retry_timers
    assert len(fake_timer.instances) == 1


def test_reap_arms_an_orphaned_pending_row_with_no_live_timer(proxy, fake_timer):
    proxy.save_cache({
        "reports": {},
        "pending": {"1.2.3.4": {"due_time": 999999999999, "severity": 2,
                                 "categories": "18", "comment": "test"}},
        "retry_queue": {},
    })
    assert "1.2.3.4" not in proxy.pending_timers

    proxy._reap_orphaned_timers()

    assert "1.2.3.4" in proxy.pending_timers
    assert proxy.pending_timers["1.2.3.4"]["severity"] == 2
    assert len(fake_timer.instances) == 1


def test_reap_leaves_a_row_with_an_existing_live_timer_alone(proxy, fake_timer):
    # The common case: almost every persisted row already has a live
    # timer in this same process. Reaping must not touch/replace it.
    proxy.save_cache({
        "reports": {"1.2.3.4": {"time": 1000, "severity": 1}},
        "pending": {},
        "retry_queue": {"1.2.3.4": {"due_time": 999999999999, "categories": "15",
                                     "comment": "test", "attempts": 2}},
    })
    existing_timer = fake_timer(0, lambda: None)
    proxy.retry_timers["1.2.3.4"] = existing_timer

    proxy._reap_orphaned_timers()

    assert proxy.retry_timers["1.2.3.4"] is existing_timer
    assert len(fake_timer.instances) == 1  # only the one we manually created


def test_reaped_retry_recovers_report_time_and_still_clears_reports_on_give_up(
    proxy, monkeypatch, fake_timer
):
    # End-to-end: an orphaned retry chain, once reaped and re-armed, must
    # behave identically to one that was never orphaned -- specifically,
    # giving up after MAX_RETRIES must still clear the "reports" entry
    # (the exact bug this whole mechanism exists to keep fixed).
    report_time = 1000
    proxy.save_cache({
        "reports": {"1.2.3.4": {"time": report_time, "severity": 1}},
        "pending": {},
        "retry_queue": {"1.2.3.4": {"due_time": 0, "categories": "15", "comment": "test",
                                     "attempts": proxy.MAX_RETRIES}},
    })

    proxy._reap_orphaned_timers()
    monkeypatch.setattr(proxy, "send_report_api", lambda ip, cats, comment: (False, None))
    fake_timer.instances[0].fire()

    assert "1.2.3.4" not in proxy.load_cache()["reports"]
    assert "1.2.3.4" not in proxy.load_cache()["retry_queue"]


def test_reap_is_a_noop_when_everything_already_has_a_live_timer(proxy, fake_timer, deferred_thread):
    # No pending/retry rows at all -> nothing to do, no timers created.
    proxy._reap_orphaned_timers()
    assert fake_timer.instances == []
