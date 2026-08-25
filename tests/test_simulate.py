"""simulate_alert() / format_simulate_text() -- side-effect-free preview
of how a categories string would be handled, for testing configuration
(severity mapping, report windows, quota reserve, comment scrubbing)
without sending a real report or needing a test IP."""
import pytest


def test_derives_severity_from_categories(proxy):
    result = proxy.simulate_alert("15,18")  # Hacking (3) + Brute-Force (2)
    assert result["severity"] == 3
    assert result["severity_name"] == "high"


def test_category_names_are_included(proxy):
    result = proxy.simulate_alert("14")
    assert result["category_names"]["14"] == "Port Scan"


def test_unknown_category_is_flagged(proxy):
    result = proxy.simulate_alert("14,999")
    assert result["unknown_categories"] == ["999"]
    assert result["category_names"]["999"] == "unknown category"


def test_report_window_defaults_to_severity_tier(make_proxy):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_HIGH="1234")
    result = p.simulate_alert("15")  # severity 3 (high)
    assert result["report_window_seconds"] == 1234
    assert "severity 3 default" in result["report_window_source"]


def test_report_window_uses_category_override_when_present(make_proxy):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_CATEGORIES="18=600")
    result = p.simulate_alert("18")
    assert result["report_window_seconds"] == 600
    assert "category override" in result["report_window_source"]
    assert "18=600s" in result["report_window_source"]


def test_multiple_category_overrides_use_the_smallest_window(make_proxy):
    p = make_proxy(ABUSEIPDB_REPORT_WINDOW_CATEGORIES="18=600,21=300")
    result = p.simulate_alert("18,21")
    assert result["report_window_seconds"] == 300


def test_quota_unknown_when_no_report_has_ever_been_sent(proxy):
    result = proxy.simulate_alert("15")
    assert result["quota_known"] is False
    assert result["quota_reserved"] is False


def test_quota_reserved_reflects_the_persisted_snapshot(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="100")
    p._update_quota_from_headers({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "50"})

    result = p.simulate_alert("14")  # severity 1 -- held back while HIGH reserve active

    assert result["quota_reserved"] is True
    assert result["quota_recheck_delay_seconds"] == p.QUOTA_RESERVE_RECHECK_DELAY


def test_quota_not_reserved_for_severity_the_reserve_does_not_cover(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="100")
    p._update_quota_from_headers({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "50"})

    result = p.simulate_alert("15")  # severity 3 -- HIGH reserve never holds back severity 3 itself

    assert result["quota_reserved"] is False


def test_comment_scrubbing_preview(make_proxy):
    p = make_proxy(ABUSEIPDB_COMMENT_SCRUB_PATTERNS=r"\d+\.\d+\.\d+\.\d+")
    result = p.simulate_alert("15", comment="seen from 10.0.0.5 repeatedly")
    assert result["comment"] == "seen from 10.0.0.5 repeatedly"
    assert "10.0.0.5" not in result["comment_after_scrubbing"]


def test_no_comment_key_when_comment_not_given(proxy):
    result = proxy.simulate_alert("15")
    assert "comment" not in result
    assert "comment_after_scrubbing" not in result


def test_format_simulate_text_includes_unknown_category_warning(proxy):
    result = proxy.simulate_alert("999")
    text = proxy.format_simulate_text(result)
    assert "999" in text
    assert "not a valid AbuseIPDB category" in text


def test_format_simulate_text_shows_held_back_state(make_proxy):
    p = make_proxy(ABUSEIPDB_QUOTA_RESERVE_HIGH="100")
    p._update_quota_from_headers({"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "50"})
    result = p.simulate_alert("14")
    text = p.format_simulate_text(result)
    assert "WOULD BE HELD BACK" in text
