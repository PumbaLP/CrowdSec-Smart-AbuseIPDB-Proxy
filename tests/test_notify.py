"""notify(): backend selection and per-backend request shape."""
import json

from conftest import SyncThread


def test_no_backend_configured_calls_nothing(proxy, sync_thread):
    proxy.notify("hello")  # must not raise even with nothing configured


def test_only_configured_backends_are_called(make_proxy, monkeypatch):
    p = make_proxy(ABUSEIPDB_NTFY_URL="https://ntfy.example.com/topic")
    monkeypatch.setattr(p.threading, "Thread", SyncThread)

    calls = []
    monkeypatch.setattr(p, "_notify_gotify", lambda msg, prio: calls.append("gotify"))
    monkeypatch.setattr(p, "_notify_ntfy", lambda msg, prio: calls.append("ntfy"))
    monkeypatch.setattr(p, "_notify_webhook", lambda msg, prio: calls.append("webhook"))

    p.notify("hello")

    assert calls == ["ntfy"]


def test_gotify_request_shape(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "GOTIFY_URL", "https://gotify.example.com")
    monkeypatch.setattr(proxy, "GOTIFY_TOKEN", "secret-token")

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_gotify("test message", "high")

    assert "secret-token" in captured["url"]
    assert captured["body"]["message"] == "test message"
    assert captured["body"]["priority"] == 8  # "high" -> Gotify priority 8


def test_ntfy_request_uses_auth_header_only_when_token_set(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "NTFY_URL", "https://ntfy.example.com/topic")
    monkeypatch.setattr(proxy, "NTFY_TOKEN", "")

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["headers"] = dict(req.headers)
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_ntfy("hi", "low")

    assert "Authorization" not in captured["headers"]


def test_a_broken_backend_never_raises(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "GOTIFY_URL", "https://gotify.example.com")
    monkeypatch.setattr(proxy, "GOTIFY_TOKEN", "token")

    def boom(req, timeout=10):
        raise OSError("network is down")

    monkeypatch.setattr(proxy.urllib.request, "urlopen", boom)

    proxy._notify_gotify("hi", "normal")  # must not raise


def test_slack_request_shape(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_slack("something failed", "high")

    assert captured["url"] == "https://hooks.slack.com/services/x"
    assert "something failed" in captured["body"]["text"]


def test_discord_request_truncates_to_2000_chars(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_discord("x" * 3000, "low")

    assert len(captured["body"]["content"]) == 2000
    assert captured["body"]["username"] == proxy.NOTIFY_NAME


def test_matrix_request_shape_and_auth(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "MATRIX_HOMESERVER_URL", "https://matrix.example.com")
    monkeypatch.setattr(proxy, "MATRIX_ACCESS_TOKEN", "secret-token")
    monkeypatch.setattr(proxy, "MATRIX_ROOM_ID", "!abc123:matrix.example.com")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_matrix("hi from the proxy", "normal")

    assert captured["method"] == "PUT"
    assert "/rooms/%21abc123%3Amatrix.example.com/send/m.room.message/" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert captured["body"]["msgtype"] == "m.text"
    assert "hi from the proxy" in captured["body"]["body"]


def test_matrix_requires_all_three_settings(proxy, monkeypatch):
    # Only the homeserver is set — missing token/room, so notify() must
    # not attempt to post (would just 401/404).
    monkeypatch.setattr(proxy, "MATRIX_HOMESERVER_URL", "https://matrix.example.com")
    calls = []
    monkeypatch.setattr(proxy, "_notify_matrix", lambda msg, prio: calls.append(1))

    proxy.notify("hi")

    assert calls == []


def test_all_backends_fire_independently(proxy, sync_thread, monkeypatch):
    monkeypatch.setattr(proxy, "GOTIFY_URL", "https://gotify.example.com")
    monkeypatch.setattr(proxy, "GOTIFY_TOKEN", "t")
    monkeypatch.setattr(proxy, "NTFY_URL", "https://ntfy.example.com/topic")
    monkeypatch.setattr(proxy, "WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setattr(proxy, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    monkeypatch.setattr(proxy, "DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/x")
    monkeypatch.setattr(proxy, "MATRIX_HOMESERVER_URL", "https://matrix.example.com")
    monkeypatch.setattr(proxy, "MATRIX_ACCESS_TOKEN", "t")
    monkeypatch.setattr(proxy, "MATRIX_ROOM_ID", "!x:matrix.example.com")
    monkeypatch.setattr(proxy, "TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setattr(proxy, "TELEGRAM_CHAT_ID", "12345")
    monkeypatch.setattr(proxy, "HOMEASSISTANT_URL", "https://ha.example.com")
    monkeypatch.setattr(proxy, "HOMEASSISTANT_TOKEN", "t")

    calls = []
    for name in ("_notify_gotify", "_notify_ntfy", "_notify_webhook",
                 "_notify_slack", "_notify_discord", "_notify_matrix",
                 "_notify_telegram", "_notify_homeassistant"):
        monkeypatch.setattr(proxy, name, (lambda n: lambda msg, prio: calls.append(n))(name))

    proxy.notify("hi")

    assert sorted(calls) == sorted([
        "_notify_gotify", "_notify_ntfy", "_notify_webhook",
        "_notify_slack", "_notify_discord", "_notify_matrix",
        "_notify_telegram", "_notify_homeassistant",
    ])


def test_telegram_request_shape(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "TELEGRAM_BOT_TOKEN", "123:ABC")
    monkeypatch.setattr(proxy, "TELEGRAM_CHAT_ID", "999")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_telegram("something failed", "high")

    assert captured["url"] == "https://api.telegram.org/bot123:ABC/sendMessage"
    assert captured["body"]["chat_id"] == "999"
    assert "something failed" in captured["body"]["text"]


def test_telegram_never_raises_on_failure(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setattr(proxy, "TELEGRAM_CHAT_ID", "1")

    def boom(req, timeout=10):
        raise OSError("network is down")

    monkeypatch.setattr(proxy.urllib.request, "urlopen", boom)
    proxy._notify_telegram("hi", "normal")  # must not raise


def test_homeassistant_request_shape_and_service_target(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "HOMEASSISTANT_URL", "https://ha.example.com")
    monkeypatch.setattr(proxy, "HOMEASSISTANT_TOKEN", "secret-token")
    monkeypatch.setattr(proxy, "HOMEASSISTANT_NOTIFY_SERVICE", "mobile_app_myphone")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_homeassistant("proxy update failed", "high")

    assert captured["url"] == "https://ha.example.com/api/services/notify/mobile_app_myphone"
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert captured["body"]["message"] == "proxy update failed"
    assert captured["body"]["data"]["priority"] == "high"


def test_homeassistant_defaults_to_the_generic_notify_service(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "HOMEASSISTANT_URL", "https://ha.example.com")
    monkeypatch.setattr(proxy, "HOMEASSISTANT_TOKEN", "t")
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        return FakeResponse()

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)

    proxy._notify_homeassistant("hi", "normal")

    assert captured["url"] == "https://ha.example.com/api/services/notify/notify"


def test_homeassistant_never_raises_on_failure(proxy, monkeypatch):
    monkeypatch.setattr(proxy, "HOMEASSISTANT_URL", "https://ha.example.com")
    monkeypatch.setattr(proxy, "HOMEASSISTANT_TOKEN", "t")

    def boom(req, timeout=10):
        raise OSError("network is down")

    monkeypatch.setattr(proxy.urllib.request, "urlopen", boom)
    proxy._notify_homeassistant("hi", "normal")  # must not raise


def test_homeassistant_requires_both_url_and_token(proxy, monkeypatch):
    # Only the URL is set — must not attempt to post (would just 401).
    monkeypatch.setattr(proxy, "HOMEASSISTANT_URL", "https://ha.example.com")
    calls = []
    monkeypatch.setattr(proxy, "_notify_homeassistant", lambda msg, prio: calls.append(1))

    proxy.notify("hi")

    assert calls == []
