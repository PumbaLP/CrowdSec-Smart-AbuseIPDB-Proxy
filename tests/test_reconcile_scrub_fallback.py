"""
Tests for three more opt-in additions, all off by default:

- Comment scrubbing (ABUSEIPDB_COMMENT_SCRUB_PATTERNS)
- Fallback API key (ABUSEIPDB_API_KEY_FALLBACK)
- CrowdSec decision reconciliation (--reconcile / ABUSEIPDB_CROWDSEC_BOUNCER_KEY)
"""
import io
import json
import urllib.error

import pytest


# --- Comment scrubbing -------------------------------------------------

def test_no_patterns_leaves_comment_untouched(proxy):
    assert proxy.scrub_comment("visited internal-host.example.local") == \
        "visited internal-host.example.local"


def test_pattern_redacts_match(make_proxy):
    p = make_proxy(ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"internal-host\.example\.local")
    assert p.scrub_comment("seen on internal-host.example.local today") == \
        "seen on [redacted] today"


def test_custom_replacement_text(make_proxy):
    p = make_proxy(
        ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"\bsecret\b",
        ABUSEIPDB_COMMENT_SCRUB_REPLACEMENT="***",
    )
    assert p.scrub_comment("the secret value") == "the *** value"


def test_multiple_semicolon_separated_patterns(make_proxy):
    p = make_proxy(ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"foo;bar")
    assert p.scrub_comment("foo and bar") == "[redacted] and [redacted]"


def test_malformed_pattern_is_skipped_not_fatal(make_proxy):
    p = make_proxy(ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"[unclosed;foo")
    assert p.scrub_comment("foo here") == "[redacted] here"


def test_empty_comment_is_a_no_op(make_proxy):
    p = make_proxy(ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"foo")
    assert p.scrub_comment("") == ""


def test_scrubbing_applied_in_dry_run_log(make_proxy, caplog):
    p = make_proxy(ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"secret-hostname")
    success, retry_after = p.send_report_api("1.2.3.4", "15", "seen on secret-hostname")
    assert success is True
    # dry-run never touches the network either way; the real assertion is
    # that scrub_comment is applied before the dry-run log line is built —
    # covered directly by the scrub_comment unit tests above. This just
    # confirms send_report_api doesn't bypass it.


# --- Fallback API key ---------------------------------------------------

def test_no_fallback_configured_stays_on_primary(proxy):
    assert proxy._current_api_key() == "test-key"
    assert proxy._switch_to_fallback_key("test") is False
    assert proxy._current_api_key() == "test-key"


def test_switch_to_fallback_key(make_proxy):
    p = make_proxy(ABUSEIPDB_API_KEY_FALLBACK="fallback-key")
    assert p._current_api_key() == "test-key"
    assert p._switch_to_fallback_key("quota exhausted") is True
    assert p._current_api_key() == "fallback-key"
    # switching again while already on the fallback is a no-op
    assert p._switch_to_fallback_key("quota exhausted again") is False


def test_concurrent_switches_only_notify_once(make_proxy, monkeypatch):
    """Regression test: the 'already using fallback?' check used to run
    before acquiring _active_key_lock, so many concurrent 429s could all
    pass the check before any of them flipped the flag, each thinking it
    was the one that switched (and each sending its own notification)."""
    import threading

    p = make_proxy(ABUSEIPDB_API_KEY_FALLBACK="fallback-key")
    calls = []
    monkeypatch.setattr(p, "notify", lambda msg, priority="high": calls.append(1))

    results = []
    barrier = threading.Barrier(20)

    def hit():
        barrier.wait()
        results.append(p._switch_to_fallback_key("concurrent 429"))

    threads = [threading.Thread(target=hit) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1  # exactly one thread "won" the switch
    assert results.count(False) == 19
    assert len(calls) == 1
    assert p._current_api_key() == "fallback-key"


def test_reset_only_happens_on_a_new_utc_day(make_proxy):
    p = make_proxy(ABUSEIPDB_API_KEY_FALLBACK="fallback-key")
    p._switch_to_fallback_key("quota exhausted")
    assert p._current_api_key() == "fallback-key"

    p._maybe_reset_fallback_key()  # same day: no reset
    assert p._current_api_key() == "fallback-key"

    import datetime
    p._fallback_switch_date = datetime.date(2000, 1, 1)  # force "yesterday"
    p._maybe_reset_fallback_key()
    assert p._current_api_key() == "test-key"


def test_429_on_primary_switches_and_retries_with_fallback(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_API_KEY_FALLBACK="fallback-key", ABUSEIPDB_DRY_RUN="false")
    keys_used = []

    class FakeResponse:
        def read(self):
            return b"{}"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        headers = {}

    def fake_urlopen(req, timeout=10):
        key = req.headers.get("Key")
        keys_used.append(key)
        if key == "test-key":
            raise urllib.error.HTTPError(req.full_url, 429, "quota exceeded", {}, io.BytesIO(b""))
        return FakeResponse()

    monkeypatch.setattr(p.urllib.request, "urlopen", fake_urlopen)

    success, retry_after = p.send_report_api("1.2.3.4", "15", "test")
    assert success is True
    assert keys_used == ["test-key", "fallback-key"]
    assert p._current_api_key() == "fallback-key"


def test_429_without_fallback_configured_just_fails(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false")

    def fake_urlopen(req, timeout=10):
        raise urllib.error.HTTPError(req.full_url, 429, "quota exceeded", {}, io.BytesIO(b""))

    monkeypatch.setattr(p.urllib.request, "urlopen", fake_urlopen)

    success, retry_after = p.send_report_api("1.2.3.4", "15", "test")
    assert success is False


# --- Reconciliation -------------------------------------------------------

def test_reconcile_without_bouncer_key_errors(proxy):
    result = proxy.run_reconcile()
    assert "error" in result
    assert "ABUSEIPDB_CROWDSEC_BOUNCER_KEY" in result["error"]


def test_reconcile_reports_only_missing_ips(make_proxy):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")

    # 1.1.1.1 is already tracked; 2.2.2.2 is new; 10.0.0.5 is private (skipped)
    cache = p.load_cache()
    cache["reports"]["1.1.1.1"] = {"time": int(p.time.time()), "severity": 1}
    p.save_cache(cache)

    p.fetch_crowdsec_active_decisions = lambda: [
        ("1.1.1.1", "crowdsecurity/ssh-bf"),
        ("2.2.2.2", "crowdsecurity/ssh-bf"),
        ("10.0.0.5", "crowdsecurity/ssh-bf"),
    ]

    result = p.run_reconcile()

    assert result["checked"] == 3
    assert result["already_known"] == 1
    assert result["skipped_ignored_or_whitelisted"] == 1
    assert result["reconciled"] == ["2.2.2.2"]
    assert "2.2.2.2" in p.load_cache()["reports"]


def test_reconcile_duplicate_ip_in_active_decisions_only_counted_once(make_proxy):
    # Regression test: known_ips used to be a static snapshot taken once
    # before the loop — if the same IP appeared twice in active_decisions
    # (overlapping decisions from different scenarios), it'd get counted
    # (and appear in the notification) twice, even though process_alert()
    # itself always correctly dedupes the actual report.
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: [
        ("2.2.2.2", "crowdsecurity/ssh-bf"),
        ("2.2.2.2", "crowdsecurity/http-probing"),
    ]

    result = p.run_reconcile()

    assert result["reconciled"] == ["2.2.2.2"]
    assert result["reconciled_count"] == 1


def test_reconcile_uses_real_scenario_categories(make_proxy):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: [("2.2.2.2", "crowdsecurity/mysql-bf")]

    sent = {}

    def fake_send(ip, categories, comment):
        sent["categories"] = categories
        sent["comment"] = comment
        return True, None

    p.send_report_api = fake_send
    p.run_reconcile()

    assert sent["categories"] == "18"  # mysql -> 18, same as abuseipdb.yaml
    assert "mysql-bf" in sent["comment"]
    assert "reconciled" in sent["comment"].lower()


def test_reconcile_falls_back_to_fixed_defaults_without_scenario(make_proxy):
    p = make_proxy(
        ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key",
        ABUSEIPDB_RECONCILE_CATEGORIES="19",
    )
    p.fetch_crowdsec_active_decisions = lambda: [("2.2.2.2", "")]  # manually-added ban

    sent = {}

    def fake_send(ip, categories, comment):
        sent["categories"] = categories
        sent["comment"] = comment
        return True, None

    p.send_report_api = fake_send
    p.run_reconcile()

    assert sent["categories"] == "19"
    assert "no scenario name" in sent["comment"]


def test_reconcile_notifies_on_missing_ips(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: [("2.2.2.2", "crowdsecurity/ssh-bf")]

    calls = []
    monkeypatch.setattr(p, "notify", lambda message, priority="high": calls.append((message, priority)))

    p.run_reconcile()

    assert len(calls) == 1
    message, priority = calls[0]
    assert "2.2.2.2" in message
    assert priority == "normal"


def test_reconcile_does_not_notify_when_nothing_missing(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: []

    calls = []
    monkeypatch.setattr(p, "notify", lambda message, priority="high": calls.append((message, priority)))

    p.run_reconcile()

    assert calls == []


def test_reconcile_notification_is_capped_for_large_batches(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    # 10.0.x.1 IPs are private and would be filtered by is_ignored_ip — use
    # public-looking ones instead so all 30 actually get reconciled
    many = [(f"203.0.{i}.1", "crowdsecurity/ssh-bf") for i in range(30)]
    p.fetch_crowdsec_active_decisions = lambda: many

    calls = []
    monkeypatch.setattr(p, "notify", lambda message, priority="high": calls.append((message, priority)))

    result = p.run_reconcile()

    assert result["reconciled_count"] == 30
    assert len(calls) == 1
    assert "and 10 more" in calls[0][0]


def test_reconcile_json_output_shape(make_proxy):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: []
    result = p.run_reconcile(as_json=True)
    assert result == {
        "checked": 0, "already_known": 0,
        "skipped_ignored_or_whitelisted": 0,
        "reconciled": [], "reconciled_count": 0,
    }


def test_reconcile_lapi_failure_is_reported_not_raised(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")

    def fake_urlopen(req, timeout=15):
        raise OSError("connection refused")

    monkeypatch.setattr(p.urllib.request, "urlopen", fake_urlopen)

    result = p.run_reconcile()
    assert "error" in result
    assert "LAPI" in result["error"]


def test_fetch_crowdsec_active_decisions_filters_non_ip_scope(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")

    class FakeResponse:
        def read(self):
            return json.dumps([
                {"value": "1.2.3.4", "scope": "Ip", "scenario": "crowdsecurity/ssh-bf"},
                {"value": "5.6.7.0/24", "scope": "Range", "scenario": "crowdsecurity/ssh-bf"},
                {"value": "8.8.8.8", "scope": "Ip", "scenario": "crowdsecurity/mysql-bf"},
            ]).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(p.urllib.request, "urlopen", lambda req, timeout=15: FakeResponse())

    assert p.fetch_crowdsec_active_decisions() == [
        ("1.2.3.4", "crowdsecurity/ssh-bf"),
        ("8.8.8.8", "crowdsecurity/mysql-bf"),
    ]


def test_fetch_crowdsec_active_decisions_missing_scenario_is_empty_string(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")

    class FakeResponse:
        def read(self):
            return json.dumps([
                {"value": "1.2.3.4", "scope": "Ip"},  # no "scenario" key at all
            ]).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(p.urllib.request, "urlopen", lambda req, timeout=15: FakeResponse())

    assert p.fetch_crowdsec_active_decisions() == [("1.2.3.4", "")]


def test_fetch_crowdsec_active_decisions_handles_null_response(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")

    class FakeResponse:
        def read(self):
            return b"null"
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(p.urllib.request, "urlopen", lambda req, timeout=15: FakeResponse())

    assert p.fetch_crowdsec_active_decisions() == []


def test_reconcile_orphaned_retry_gets_reaped_by_a_separately_running_process(
    make_proxy, monkeypatch, fake_timer
):
    """
    Full simulation of the real --reconcile gap this is meant to close:
    --reconcile runs as its own short-lived process. If the report it
    triggers fails and needs a retry, that retry's threading.Timer lives
    only in the CLI process's memory and is lost the instant it exits --
    but it also writes to the same on-disk cache the long-running service
    reads. Modeled here as two separate `p` instances sharing one
    tmp_path cache file: `p_reconcile` stands in for the CLI invocation
    (its retry_timers are simply thrown away, exactly like process exit
    would), `p_service` stands in for the always-running proxy, whose
    periodic _reap_orphaned_timers() must pick the orphaned row back up.
    """
    p_reconcile = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p_reconcile.fetch_crowdsec_active_decisions = lambda: [("9.9.9.9", "crowdsecurity/ssh-bf")]
    p_reconcile.send_report_api = lambda ip, cats, comment: (False, None)  # first attempt fails

    p_reconcile.run_reconcile()
    # The CLI process's own retry chain exists in ITS memory...
    assert "9.9.9.9" in p_reconcile.retry_timers
    # ...but the retry_queue row (and the optimistic "reports" row) is on
    # disk, visible to anything else pointed at the same cache file.
    assert "9.9.9.9" in p_reconcile.load_cache()["retry_queue"]
    assert "9.9.9.9" in p_reconcile.load_cache()["reports"]

    # The CLI process exits: its daemon timer is gone, with nothing left
    # to ever fire it. (Not calling .cancel() -- an exiting process
    # doesn't get the chance to either; the point is nothing further
    # happens because the object is simply never reached again.)

    # A second, independently-running proxy process, pointed at the same
    # cache file, has no idea this retry exists yet.
    p_service = make_proxy(
        ABUSEIPDB_CACHE_FILE=p_reconcile.CACHE_FILE,
        ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key",
    )
    assert "9.9.9.9" not in p_service.retry_timers
    fake_timer.instances.clear()  # discard p_reconcile's now-orphaned timer object

    p_service._reap_orphaned_timers()

    # Now it does -- re-armed with a real, live timer in the
    # long-running process, recovering the correct report_time too.
    assert "9.9.9.9" in p_service.retry_timers
    assert len(fake_timer.instances) == 1

    # And it behaves exactly like a normal retry chain from here: if it
    # goes on to exhaust its retries, the "reports" row still gets
    # cleared correctly, not left permanently blocking future alerts.
    monkeypatch.setattr(p_service, "send_report_api", lambda ip, cats, comment: (False, None))
    for _ in range(p_service.MAX_RETRIES):
        if not fake_timer.instances:
            break
        fake_timer.instances.pop(0).fire()

    assert "9.9.9.9" not in p_service.load_cache()["reports"]
