"""is_ignored_ip(): private/reserved/CGNAT filtering, on by default."""
import pytest


@pytest.mark.parametrize("ip", [
    "192.168.1.1",   # RFC1918
    "10.0.0.5",      # RFC1918
    "172.16.0.1",    # RFC1918
    "127.0.0.1",     # loopback
    "169.254.1.1",   # link-local
    "100.88.148.126",  # CGNAT / Tailscale range
    "::1",            # IPv6 loopback
    "fe80::1",        # IPv6 link-local
    "fc00::1",        # IPv6 unique local
])
def test_private_and_reserved_ips_are_ignored_by_default(proxy, ip):
    assert proxy.is_ignored_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "1.1.1.1",
    "8.8.8.8",
    "203.0.113.5",  # TEST-NET-3, publicly routable range
    "2606:4700:4700::1111",
])
def test_public_ips_are_never_ignored(proxy, ip):
    assert proxy.is_ignored_ip(ip) is False


def test_malformed_ip_is_not_ignored(proxy):
    # Let AbuseIPDB reject a malformed IP with a clear error rather than
    # silently swallowing it here.
    assert proxy.is_ignored_ip("not-an-ip") is False


def test_ignore_private_false_disables_default_filtering(make_proxy):
    p = make_proxy(ABUSEIPDB_IGNORE_PRIVATE="false")
    assert p.is_ignored_ip("192.168.1.1") is False


def test_extra_ignore_ips_are_added_on_top_of_defaults(make_proxy):
    p = make_proxy(ABUSEIPDB_IGNORE_IPS="203.0.113.5,198.51.100.0/24")
    assert p.is_ignored_ip("203.0.113.5") is True
    assert p.is_ignored_ip("198.51.100.42") is True
    # defaults still apply alongside the custom entries
    assert p.is_ignored_ip("10.0.0.1") is True
    # untouched public IPs remain reportable
    assert p.is_ignored_ip("1.1.1.1") is False


def test_malformed_ignore_ips_entry_is_skipped_not_fatal(make_proxy):
    # A typo in ABUSEIPDB_IGNORE_IPS must not crash the whole proxy on
    # startup — it should just be skipped (with a warning on stderr).
    p = make_proxy(ABUSEIPDB_IGNORE_IPS="not-a-cidr,203.0.113.5")
    assert p.is_ignored_ip("203.0.113.5") is True
