"""
process_alert(): the core "report / suppress / delay" decision.

Uses deferred_thread (runs the immediate-report thread synchronously) and
fake_timer (captures delayed-escalation timers instead of really
waiting) so the whole decision tree can be tested without real time
passing or any network access.
"""
import time


def test_new_ip_is_reported_immediately(proxy, deferred_thread):
    proxy.process_alert("1.2.3.4", "15", "SSH brute-force", new_severity=2)

    cache = proxy.load_cache()
    assert "1.2.3.4" in cache["reports"]
    assert cache["reports"]["1.2.3.4"]["severity"] == 2


def test_repeat_alert_with_same_severity_is_suppressed(proxy, deferred_thread):
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    proxy.process_alert("1.2.3.4", "14", "port scan again", new_severity=1)

    assert proxy.metrics["reports_suppressed_total"] == 1
    # still only the original report recorded, no re-report
    assert proxy.load_cache()["reports"]["1.2.3.4"]["time"] > 0


def test_repeat_alert_with_lower_severity_is_suppressed(proxy, deferred_thread):
    proxy.process_alert("1.2.3.4", "15", "hacking", new_severity=3)
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)

    assert proxy.metrics["reports_suppressed_total"] == 1
    assert proxy.load_cache()["reports"]["1.2.3.4"]["severity"] == 3  # unchanged


def test_escalation_outside_the_report_window_is_reported_immediately(proxy, deferred_thread, monkeypatch):
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)

    cache = proxy.load_cache()
    cache["reports"]["1.2.3.4"]["time"] -= 10_000  # long past any report window
    proxy.save_cache(cache)

    proxy.process_alert("1.2.3.4", "15", "hacking", new_severity=3)

    cache = proxy.load_cache()
    assert cache["reports"]["1.2.3.4"]["severity"] == 3
    assert len(proxy.pending_timers) == 0


def test_escalation_within_the_report_window_is_delayed_not_dropped(proxy, fake_timer, deferred_thread):
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    proxy.process_alert("1.2.3.4", "15", "hacking", new_severity=3)

    # Not reported yet: dedup entry still reflects the original low
    # severity, and there's exactly one pending escalation timer scheduled.
    assert proxy.load_cache()["reports"]["1.2.3.4"]["severity"] == 1
    assert "1.2.3.4" in proxy.pending_timers
    assert len(fake_timer.instances) == 1
    assert fake_timer.instances[0].function == proxy._finalize_pending

    pending_cache = proxy.load_cache()["pending"]["1.2.3.4"]
    assert pending_cache["severity"] == 3
    assert pending_cache["categories"] == "15"


def test_delayed_escalation_fires_and_updates_the_report(proxy, fake_timer, deferred_thread):
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)
    proxy.process_alert("1.2.3.4", "15", "hacking", new_severity=3)

    fake_timer.instances[0].fire()

    cache = proxy.load_cache()
    assert cache["reports"]["1.2.3.4"]["severity"] == 3
    assert "1.2.3.4" not in cache["pending"]
    assert "1.2.3.4" not in proxy.pending_timers


def test_second_escalation_replaces_a_lower_pending_one(proxy, fake_timer, deferred_thread):
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)       # low, reported
    proxy.process_alert("1.2.3.4", "18", "brute-force", new_severity=2)     # medium, pending
    first_pending = fake_timer.instances[0]

    proxy.process_alert("1.2.3.4", "15", "hacking", new_severity=3)         # high, replaces pending

    assert first_pending.cancelled is True
    assert proxy.load_cache()["pending"]["1.2.3.4"]["severity"] == 3
    assert proxy.pending_timers["1.2.3.4"]["severity"] == 3


def test_second_escalation_at_or_below_pending_severity_is_suppressed(proxy, fake_timer, deferred_thread):
    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)   # low, reported
    proxy.process_alert("1.2.3.4", "15", "hacking", new_severity=3)     # high, pending
    first_pending = fake_timer.instances[0]

    proxy.process_alert("1.2.3.4", "18", "brute-force", new_severity=2)  # lower than the pending escalation

    assert first_pending.cancelled is False
    assert proxy.metrics["reports_suppressed_total"] == 1
    assert proxy.pending_timers["1.2.3.4"]["severity"] == 3  # unchanged


def test_reports_older_than_24h_are_pruned_and_treated_as_new(proxy, deferred_thread):
    proxy.save_cache({
        "reports": {"1.2.3.4": {"time": int(time.time()) - 90_000, "severity": 3}},  # > 24h old
        "pending": {},
        "retry_queue": {},
    })

    proxy.process_alert("1.2.3.4", "14", "port scan", new_severity=1)

    cache = proxy.load_cache()
    assert cache["reports"]["1.2.3.4"]["severity"] == 1  # fresh report, not an "escalation"
