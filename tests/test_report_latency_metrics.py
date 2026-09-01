"""_record_report_latency() and its exposure via /metrics as a standard
Prometheus histogram -- how long each AbuseIPDB API call actually takes,
complementing the existing pass/fail counters."""
import json
import urllib.request

import pytest


def test_observation_increments_every_bucket_at_or_above_its_value(proxy):
    proxy._record_report_latency(0.05)
    for i, upper in enumerate(proxy._REPORT_LATENCY_BUCKETS):
        assert proxy._report_latency_bucket_counts[i] == (1 if upper >= 0.05 else 0)
    assert proxy._report_latency_bucket_counts[-1] == 1  # +Inf


def test_cumulative_semantics_across_multiple_observations(proxy):
    # Buckets are [0.1, 0.25, 0.5, 1, 2, 5, 10, 20]. Four observations
    # spanning different buckets -- each bucket must count every
    # observation at or under its own boundary, not just ones that
    # "belong" specifically to it.
    for v in (0.05, 0.3, 3.0, 15.0):
        proxy._record_report_latency(v)

    counts = dict(zip(proxy._REPORT_LATENCY_BUCKETS, proxy._report_latency_bucket_counts))
    assert counts[0.1] == 1    # just 0.05
    assert counts[0.25] == 1   # still just 0.05
    assert counts[0.5] == 2    # 0.05, 0.3
    assert counts[5] == 3      # 0.05, 0.3, 3.0
    assert counts[20] == 4     # all four
    assert proxy._report_latency_bucket_counts[-1] == 4  # +Inf: always all of them


def test_sum_and_count_are_tracked(proxy):
    proxy._record_report_latency(0.05)
    proxy._record_report_latency(0.3)
    assert proxy._report_latency_count == 2
    assert proxy._report_latency_sum == pytest.approx(0.35)


def test_an_observation_above_every_bucket_only_lands_in_plus_inf(proxy):
    proxy._record_report_latency(999)
    assert proxy._report_latency_bucket_counts[:-1] == [0] * len(proxy._REPORT_LATENCY_BUCKETS)
    assert proxy._report_latency_bucket_counts[-1] == 1


def test_send_report_api_records_a_latency_observation_on_success(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false", ABUSEIPDB_API_KEY="test-key")
    monkeypatch.setattr(
        p.urllib.request, "urlopen",
        lambda req, timeout=10: FakeResponse(),
    )
    assert p._report_latency_count == 0
    p.send_report_api("1.2.3.4", "15", "test")
    assert p._report_latency_count == 1


def test_send_report_api_records_a_latency_observation_on_failure(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_DRY_RUN="false", ABUSEIPDB_API_KEY="test-key")

    def raise_error(req, timeout=10):
        raise OSError("connection refused")

    monkeypatch.setattr(p.urllib.request, "urlopen", raise_error)
    assert p._report_latency_count == 0
    p.send_report_api("1.2.3.4", "15", "test")
    assert p._report_latency_count == 1


def test_dry_run_does_not_record_a_latency_observation(make_proxy):
    p = make_proxy(ABUSEIPDB_DRY_RUN="true")
    p.send_report_api("1.2.3.4", "15", "test")
    assert p._report_latency_count == 0


class FakeHeaders(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class FakeResponse:
    status = 200
    headers = FakeHeaders()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return b""


def test_metrics_endpoint_exposes_the_histogram(running_server):
    p, base_url = running_server(ABUSEIPDB_DRY_RUN="true", ABUSEIPDB_ENABLE_METRICS="true")
    p._record_report_latency(0.05)
    p._record_report_latency(3.0)

    with urllib.request.urlopen(base_url + "/metrics", timeout=5) as resp:
        body = resp.read().decode()

    assert "# TYPE abuseipdb_proxy_report_latency_seconds histogram" in body
    assert 'abuseipdb_proxy_report_latency_seconds_bucket{le="0.1"} 1' in body
    assert 'abuseipdb_proxy_report_latency_seconds_bucket{le="+Inf"} 2' in body
    assert "abuseipdb_proxy_report_latency_seconds_sum 3.05" in body
    assert "abuseipdb_proxy_report_latency_seconds_count 2" in body
