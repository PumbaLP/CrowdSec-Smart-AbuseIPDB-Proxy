"""
Dedicated IPv6 audit. tests/test_ip_filtering.py already covers the
basic is_ignored_ip() default-private-ranges case for IPv6; this file
covers everything else that touches an IP: the source-IP allowlist,
custom ignore entries with an IPv6 CIDR, CrowdSec decision scope
filtering, and a full end-to-end request through the real running
server (not just the individual functions in isolation).
"""
import json
import urllib.request

import pytest


# --- Custom ignore entries with an IPv6 CIDR --------------------------------

def test_custom_ignore_ips_accepts_ipv6_cidr(make_proxy):
    p = make_proxy(ABUSEIPDB_IGNORE_IPS="2001:db8::/32")
    assert p.is_ignored_ip("2001:db8::1") is True
    assert p.is_ignored_ip("2001:db8:1234::5678") is True
    # a different, non-matching IPv6 prefix is untouched
    assert p.is_ignored_ip("2606:4700:4700::1111") is False


def test_mixed_ipv4_and_ipv6_entries_in_ignore_ips(make_proxy):
    p = make_proxy(ABUSEIPDB_IGNORE_IPS="203.0.113.0/24,2001:db8::/32")
    assert p.is_ignored_ip("203.0.113.5") is True
    assert p.is_ignored_ip("2001:db8::1") is True
    assert p.is_ignored_ip("1.1.1.1") is False
    assert p.is_ignored_ip("2606:4700:4700::1111") is False


# --- Source-IP allowlist (ABUSEIPDB_ALLOWED_SOURCE_IPS) ---------------------

def test_allowlist_accepts_ipv6_cidr(make_proxy):
    p = make_proxy(ABUSEIPDB_ALLOWED_SOURCE_IPS="2001:db8::/32")
    assert p.is_source_ip_allowed("2001:db8::1") is True
    assert p.is_source_ip_allowed("2606:4700:4700::1111") is False


def test_allowlist_accepts_single_ipv6_address(make_proxy):
    p = make_proxy(ABUSEIPDB_ALLOWED_SOURCE_IPS="::1")
    assert p.is_source_ip_allowed("::1") is True
    assert p.is_source_ip_allowed("::2") is False


def test_allowlist_mixed_v4_and_v6_entries(make_proxy):
    p = make_proxy(ABUSEIPDB_ALLOWED_SOURCE_IPS="127.0.0.1,::1")
    assert p.is_source_ip_allowed("127.0.0.1") is True
    assert p.is_source_ip_allowed("::1") is True
    assert p.is_source_ip_allowed("203.0.113.5") is False
    assert p.is_source_ip_allowed("2001:db8::1") is False


# --- CrowdSec decision reconciliation ---------------------------------------

def test_fetch_crowdsec_active_decisions_includes_ipv6_scope_ip(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")

    class FakeResponse:
        def read(self):
            # CrowdSec doesn't distinguish v4/v6 in the "scope" field —
            # both are just "Ip"
            return json.dumps([
                {"value": "2606:4700:4700::1111", "scope": "Ip", "scenario": "crowdsecurity/ssh-bf"},
                {"value": "2001:db8::/32", "scope": "Range", "scenario": "crowdsecurity/ssh-bf"},
            ]).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(p.urllib.request, "urlopen", lambda req, timeout=15: FakeResponse())

    assert p.fetch_crowdsec_active_decisions() == [("2606:4700:4700::1111", "crowdsecurity/ssh-bf")]


def test_reconcile_reports_a_new_ipv6_ip(make_proxy):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: [("2606:4700:4700::1111", "crowdsecurity/ssh-bf")]

    result = p.run_reconcile()

    assert result["reconciled"] == ["2606:4700:4700::1111"]
    assert "2606:4700:4700::1111" in p.load_cache()["reports"]


def test_reconcile_still_skips_private_ipv6(make_proxy):
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY="test-bouncer-key")
    p.fetch_crowdsec_active_decisions = lambda: [("fc00::1", "crowdsecurity/ssh-bf")]

    result = p.run_reconcile()

    assert result["reconciled"] == []
    assert result["skipped_ignored_or_whitelisted"] == 1


# --- Full end-to-end through the real running server ------------------------

def test_report_and_dedup_an_ipv6_ip_end_to_end(running_server):
    p, base_url = running_server()

    body = json.dumps({"ip": "2606:4700:4700::1111", "categories": "15", "comment": "test"}).encode()
    req = urllib.request.Request(base_url + "/", data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200

    cache = p.load_cache()
    assert "2606:4700:4700::1111" in cache["reports"]

    # a second alert for the same IPv6 IP, same severity, must dedup
    # exactly like an IPv4 one would
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200

    with p.metrics_lock:
        assert p.metrics.get("reports_suppressed_total", 0) == 1


def test_private_ipv6_is_never_reported_end_to_end(running_server):
    p, base_url = running_server()

    body = json.dumps({"ip": "fc00::1", "categories": "15", "comment": "test"}).encode()
    req = urllib.request.Request(base_url + "/", data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200

    assert "fc00::1" not in p.load_cache()["reports"]
    with p.metrics_lock:
        assert p.metrics.get("reports_ignored_private_total", 0) == 1
