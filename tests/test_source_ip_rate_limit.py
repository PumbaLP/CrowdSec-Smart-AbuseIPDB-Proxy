"""_check_source_ip_rate_limit() / _prune_source_ip_rate_limit_state() --
per-source-ip request throttling, complementary to the global
MAX_CONCURRENT_REQUESTS ceiling (which caps total concurrency across every
source combined, but does nothing to stop one single source from
consuming most or all of that shared pool)."""
import json
import urllib.error
import urllib.request

import pytest


def _post(base_url, ip, categories="15", comment="test"):
    body = json.dumps({"ip": ip, "categories": categories, "comment": comment}).encode("utf-8")
    req = urllib.request.Request(base_url + "/", data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_disabled_by_default(proxy):
    assert proxy.MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE == 0
    # With it disabled, nothing is ever rejected no matter how many calls.
    for _ in range(1000):
        assert proxy._check_source_ip_rate_limit("1.2.3.4") is True


def test_allows_requests_up_to_the_limit(make_proxy):
    p = make_proxy(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="5")
    for _ in range(5):
        assert p._check_source_ip_rate_limit("1.2.3.4") is True


def test_rejects_the_request_over_the_limit(make_proxy):
    p = make_proxy(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="3")
    for _ in range(3):
        assert p._check_source_ip_rate_limit("1.2.3.4") is True
    assert p._check_source_ip_rate_limit("1.2.3.4") is False


def test_different_source_ips_are_tracked_independently(make_proxy):
    p = make_proxy(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="1")
    assert p._check_source_ip_rate_limit("1.1.1.1") is True
    # A different ip having already used its own allowance doesn't affect
    # this one -- each source ip gets its own independent budget.
    assert p._check_source_ip_rate_limit("2.2.2.2") is True
    assert p._check_source_ip_rate_limit("1.1.1.1") is False
    assert p._check_source_ip_rate_limit("2.2.2.2") is False


def test_sliding_window_allows_a_new_request_once_the_oldest_ages_out(make_proxy):
    p = make_proxy(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="2")
    assert p._check_source_ip_rate_limit("1.2.3.4") is True
    assert p._check_source_ip_rate_limit("1.2.3.4") is True
    assert p._check_source_ip_rate_limit("1.2.3.4") is False

    # Age the first of the two recorded requests out of the window --
    # a sliding window (not a fixed per-minute bucket) should let exactly
    # one new request back in, not reset the whole budget.
    p._source_ip_request_times["1.2.3.4"][0] -= p._SOURCE_IP_RATE_WINDOW_SECONDS + 1

    assert p._check_source_ip_rate_limit("1.2.3.4") is True
    assert p._check_source_ip_rate_limit("1.2.3.4") is False


def test_prune_drops_an_ip_whose_entire_window_has_aged_out(make_proxy):
    p = make_proxy(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="5")
    p._check_source_ip_rate_limit("1.2.3.4")
    assert "1.2.3.4" in p._source_ip_request_times

    for t in p._source_ip_request_times["1.2.3.4"]:
        pass
    p._source_ip_request_times["1.2.3.4"] = [
        t - p._SOURCE_IP_RATE_WINDOW_SECONDS - 1 for t in p._source_ip_request_times["1.2.3.4"]
    ]

    p._prune_source_ip_rate_limit_state()

    assert "1.2.3.4" not in p._source_ip_request_times


def test_prune_keeps_an_ip_with_still_relevant_entries(make_proxy):
    p = make_proxy(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="5")
    p._check_source_ip_rate_limit("1.2.3.4")

    p._prune_source_ip_rate_limit_state()

    assert "1.2.3.4" in p._source_ip_request_times


def test_prune_is_a_noop_on_an_empty_state(proxy):
    proxy._prune_source_ip_rate_limit_state()  # must not raise
    assert proxy._source_ip_request_times == {}


def test_real_http_requests_over_the_limit_get_429(running_server):
    p, base_url = running_server(ABUSEIPDB_MAX_REQUESTS_PER_SOURCE_IP_PER_MINUTE="3", ABUSEIPDB_DRY_RUN="true")

    statuses = []
    for i in range(5):
        status, _ = _post(base_url, f"203.0.113.{i}")
        statuses.append(status)

    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
    assert statuses[4] == 429


def test_rate_limit_disabled_by_default_over_real_http(running_server):
    p, base_url = running_server(ABUSEIPDB_DRY_RUN="true")
    for i in range(20):
        status, _ = _post(base_url, f"203.0.113.{i}")
        assert status == 200
