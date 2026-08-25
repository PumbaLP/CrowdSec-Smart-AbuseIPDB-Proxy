"""_sd_notify() -- best-effort systemd readiness/shutdown notification via
$NOTIFY_SOCKET, only meaningful under a Type=notify unit."""
import os
import socket

import pytest


def test_noop_when_notify_socket_is_not_set(proxy, monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    # Must not raise, must not attempt any socket I/O.
    proxy._sd_notify("READY=1")


def test_sends_the_state_string_to_the_real_unix_socket(proxy, monkeypatch, tmp_path):
    sock_path = str(tmp_path / "notify.sock")
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server_sock.bind(sock_path)
    server_sock.settimeout(2)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", sock_path)
        proxy._sd_notify("READY=1")
        data, _ = server_sock.recvfrom(1024)
        assert data == b"READY=1"
    finally:
        server_sock.close()


def test_abstract_namespace_socket_prefix_is_translated(proxy, monkeypatch):
    # "@name" is systemd/sd_notify's convention for an abstract-namespace
    # unix socket (no filesystem path) -- must be translated to a leading
    # NUL byte, which is what AF_UNIX actually expects for that.
    captured = {}

    class FakeSocket:
        def __init__(self, *a, **kw):
            pass

        def connect(self, addr):
            captured["addr"] = addr

        def sendall(self, data):
            captured["data"] = data

        def close(self):
            pass

    monkeypatch.setattr(proxy.socket, "socket", lambda *a, **kw: FakeSocket())
    monkeypatch.setenv("NOTIFY_SOCKET", "@abuseipdb-proxy-test")

    proxy._sd_notify("STOPPING=1")

    assert captured["addr"] == "\0abuseipdb-proxy-test"
    assert captured["data"] == b"STOPPING=1"


def test_broken_socket_does_not_raise(proxy, monkeypatch):
    # A stale/nonexistent socket path (e.g. systemd restarted the socket,
    # or NOTIFY_SOCKET is just misconfigured) must never be able to crash
    # startup or block a shutdown -- this is always best-effort.
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/path/does/not/exist.sock")
    proxy._sd_notify("READY=1")  # must not raise
