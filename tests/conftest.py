"""
Shared fixtures for the test suite.

abuseipdb_proxy.py is a single script, not a package, and it reads its
configuration from environment variables at *import* time (VERSION,
CACHE_FILE, MAX_RETRIES, the notification backend URLs, ...). To test
different configurations without leaking state between tests, every test
gets its own freshly-imported copy of the module via `make_proxy()` /
the `proxy` fixture below, instead of importing it once at collection
time.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "abuseipdb_proxy.py"

# Env vars the module reads at import time. Cleared before every test so
# a developer's real ~/.bashrc exports (or a previous test's monkeypatch)
# can never leak into a test — most importantly, so tests never
# accidentally have a real Gotify/ntfy/webhook backend configured and
# fire a real HTTP request.
_ENV_VARS_UNDER_TEST = (
    "ABUSEIPDB_API_KEY",
    "ABUSEIPDB_PROXY_PORT",
    "ABUSEIPDB_LISTEN_ADDRESS",
    "ABUSEIPDB_CACHE_FILE",
    "ABUSEIPDB_CACHE_BACKEND",
    "ABUSEIPDB_SQLITE_JOURNAL_MODE",
    "ABUSEIPDB_SQLITE_SYNCHRONOUS",
    "ABUSEIPDB_REPORT_WINDOW",
    "ABUSEIPDB_REPORT_WINDOW_LOW",
    "ABUSEIPDB_REPORT_WINDOW_MEDIUM",
    "ABUSEIPDB_REPORT_WINDOW_HIGH",
    "ABUSEIPDB_MAX_RETRIES",
    "ABUSEIPDB_RETRY_DELAY",
    "ABUSEIPDB_DRY_RUN",
    "ABUSEIPDB_VERBOSE_LOGGING",
    "ABUSEIPDB_LOG_FORMAT",
    "ABUSEIPDB_QUOTA_WARN_THRESHOLD",
    "ABUSEIPDB_BACKUP_RETENTION",
    "ABUSEIPDB_SUMMARY_INTERVAL",
    "ABUSEIPDB_ENABLE_HEALTH",
    "ABUSEIPDB_ENABLE_METRICS",
    "ABUSEIPDB_NOTIFY_ON_START",
    "ABUSEIPDB_IGNORE_PRIVATE",
    "ABUSEIPDB_IGNORE_IPS",
    "ABUSEIPDB_NOTIFY_NAME",
    "ABUSEIPDB_GOTIFY_URL",
    "ABUSEIPDB_GOTIFY_TOKEN",
    "ABUSEIPDB_NTFY_URL",
    "ABUSEIPDB_NTFY_TOKEN",
    "ABUSEIPDB_WEBHOOK_URL",
    "ABUSEIPDB_SLACK_WEBHOOK_URL",
    "ABUSEIPDB_DISCORD_WEBHOOK_URL",
    "ABUSEIPDB_MATRIX_HOMESERVER_URL",
    "ABUSEIPDB_MATRIX_ACCESS_TOKEN",
    "ABUSEIPDB_MATRIX_ROOM_ID",
    "ABUSEIPDB_TELEGRAM_BOT_TOKEN",
    "ABUSEIPDB_TELEGRAM_CHAT_ID",
    "ABUSEIPDB_HOMEASSISTANT_URL",
    "ABUSEIPDB_HOMEASSISTANT_TOKEN",
    "ABUSEIPDB_HOMEASSISTANT_NOTIFY_SERVICE",
    "ABUSEIPDB_REPORT_WINDOW_CATEGORIES",
    "ABUSEIPDB_ALLOWED_SOURCE_IPS",
    "ABUSEIPDB_SHARED_SECRET",
    "ABUSEIPDB_QUOTA_RESERVE_MEDIUM",
    "ABUSEIPDB_QUOTA_RESERVE_HIGH",
    "ABUSEIPDB_SKIP_WHITELISTED",
    "ABUSEIPDB_WHITELIST_CACHE_TTL",
    "ABUSEIPDB_COMMENT_SCRUB_PATTERNS",
    "ABUSEIPDB_COMMENT_SCRUB_REPLACEMENT",
    "ABUSEIPDB_API_KEY_FALLBACK",
    "ABUSEIPDB_CROWDSEC_LAPI_URL",
    "ABUSEIPDB_CROWDSEC_BOUNCER_KEY",
    "ABUSEIPDB_RECONCILE_SEVERITY",
    "ABUSEIPDB_RECONCILE_CATEGORIES",
    "ABUSEIPDB_API_KEY_FILE",
    "ABUSEIPDB_API_KEY_FALLBACK_FILE",
    "ABUSEIPDB_CROWDSEC_BOUNCER_KEY_FILE",
    "ABUSEIPDB_SHARED_SECRET_FILE",
    "ABUSEIPDB_GOTIFY_TOKEN_FILE",
    "ABUSEIPDB_NTFY_TOKEN_FILE",
    "ABUSEIPDB_WEBHOOK_URL_FILE",
    "ABUSEIPDB_SLACK_WEBHOOK_URL_FILE",
    "ABUSEIPDB_DISCORD_WEBHOOK_URL_FILE",
    "ABUSEIPDB_MATRIX_ACCESS_TOKEN_FILE",
    "ABUSEIPDB_TELEGRAM_BOT_TOKEN_FILE",
    "ABUSEIPDB_HOMEASSISTANT_TOKEN_FILE",
)


def _load_fresh_module():
    """Import abuseipdb_proxy.py as a brand-new module object (not via
    sys.modules caching), so each test gets an independent copy of all
    module-level state: metrics counters, pending_timers, retry_timers,
    and the env-derived config constants."""
    spec = importlib.util.spec_from_file_location(
        "abuseipdb_proxy_under_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def make_proxy(monkeypatch, tmp_path):
    """Factory fixture: make_proxy(**env) returns a freshly-imported proxy
    module configured with the given environment variables (plus sane
    defaults: a dummy API key, an isolated per-test cache file on the
    SQLite backend — the only one since 3.0.0 — and dry-run mode)."""

    def _make(**env_overrides):
        for var in _ENV_VARS_UNDER_TEST:
            monkeypatch.delenv(var, raising=False)

        env = {
            "ABUSEIPDB_API_KEY": "test-key",
            "ABUSEIPDB_CACHE_FILE": str(tmp_path / "cache.db"),
            "ABUSEIPDB_DRY_RUN": "true",
        }
        env.update(env_overrides)
        for key, value in env.items():
            monkeypatch.setenv(key, value)

        return _load_fresh_module()

    return _make


@pytest.fixture
def proxy(make_proxy):
    """A freshly-imported proxy module with default test config. Use
    make_proxy(**env) directly instead when a test needs specific
    environment variables set."""
    module = make_proxy()
    yield module

    # Defensive cleanup: cancel any timers a test armed (delayed
    # escalations, retries) so no stray background thread can fire after
    # the test — and its tmp_path — is gone.
    for info in module.pending_timers.values():
        info["timer"].cancel()
    for timer in module.retry_timers.values():
        timer.cancel()


class FakeTimer:
    """
    Drop-in replacement for threading.Timer that never actually waits.
    .start() just records the call instead of scheduling a real thread,
    so tests can assert on *what* was scheduled (delay, target, args)
    without waiting in real time. Call .fire() to run the callback,
    simulating the delay having elapsed.
    """
    instances = []

    def __init__(self, interval, function, args=None, kwargs=None):
        self.interval = interval
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.started = False
        self.cancelled = False
        FakeTimer.instances.append(self)

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True

    def fire(self):
        if not self.cancelled:
            self.function(*self.args, **self.kwargs)


@pytest.fixture
def fake_timer(proxy, monkeypatch):
    """Patches proxy.threading.Timer with FakeTimer for the test. Use for
    tests that need to inspect or manually trigger a delayed escalation
    report or a queued retry."""
    FakeTimer.instances = []
    monkeypatch.setattr(proxy.threading, "Timer", FakeTimer)
    yield FakeTimer


class SyncThread:
    """Drop-in replacement for threading.Thread that runs its target
    synchronously in .start(), so tests don't need to sleep/poll for a
    background thread to finish before asserting on its side effects."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)

    def join(self, timeout=None):
        pass


@pytest.fixture
def sync_thread(proxy, monkeypatch):
    """Patches proxy.threading.Thread with SyncThread for the test. Safe
    for code paths that start a thread *outside* any lock they hold
    (e.g. notify(), _finalize_pending()). Do NOT use this for
    process_alert()'s immediate-report path — see deferred_thread."""
    monkeypatch.setattr(proxy.threading, "Thread", SyncThread)
    yield SyncThread


class DeferredThread:
    """
    Like SyncThread, but .start() only *records* the call instead of
    running it immediately. process_alert() starts its immediate-report
    thread while still holding the module's lock; running that thread
    inline (as SyncThread does) would re-enter send_with_retry's own
    `with lock:` on the same thread and deadlock. Call .run_all() after
    the call that scheduled the work returns (i.e. once the lock has
    been released) to actually execute it.
    """
    pending = []

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        DeferredThread.pending.append((self._target, self._args, self._kwargs))

    def join(self, timeout=None):
        pass

    @classmethod
    def run_all(cls):
        pending, cls.pending = cls.pending, []
        for target, args, kwargs in pending:
            if target:
                target(*args, **kwargs)


@pytest.fixture
def deferred_thread(proxy, monkeypatch):
    """Patches proxy.threading.Thread with DeferredThread. Use for any
    test that calls process_alert() directly and needs the resulting
    immediate report to actually run: call deferred_thread.run_all()
    after process_alert() returns."""
    DeferredThread.pending = []
    monkeypatch.setattr(proxy.threading, "Thread", DeferredThread)
    yield DeferredThread


@pytest.fixture
def running_server(make_proxy):
    """Starts a real ThreadingHTTPServer for a freshly-made proxy module
    on an OS-assigned free port, and tears it down after the test. Yields
    a factory: call it (optionally with env var overrides, same as
    make_proxy) to get (proxy_module, base_url). Shared across any test
    file that needs to exercise real concurrent HTTP behavior rather than
    calling functions directly in a single test thread."""
    import threading as _threading

    def _start(**env_overrides):
        p = make_proxy(**env_overrides)
        server = p.http.server.ThreadingHTTPServer(("127.0.0.1", 0), p.AbuseIPDBHandler)
        server.daemon_threads = True
        server.request_queue_size = 128  # match main()'s production setting
        thread = _threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        _start.servers.append(server)
        return p, f"http://127.0.0.1:{port}"

    _start.servers = []
    yield _start
    for server in _start.servers:
        server.shutdown()
        server.server_close()
