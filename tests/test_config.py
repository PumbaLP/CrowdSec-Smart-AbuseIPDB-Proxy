"""ABUSEIPDB_LISTEN_ADDRESS: defaults to 127.0.0.1 (bare-metal-safe), overridable for Docker."""


def test_defaults_to_localhost_only(proxy):
    assert proxy.LISTEN_ADDRESS == "127.0.0.1"


def test_overridable_for_docker(make_proxy):
    p = make_proxy(ABUSEIPDB_LISTEN_ADDRESS="0.0.0.0")
    assert p.LISTEN_ADDRESS == "0.0.0.0"
