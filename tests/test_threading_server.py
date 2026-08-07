"""
Integration tests that actually spin up the real ThreadingHTTPServer and
fire concurrent HTTP requests at it — the class of race conditions fixed
alongside the HTTPServer -> ThreadingHTTPServer switch (dedup correctness
under real concurrency, the whitelist-check-blocks-everyone-else
limitation) can only be demonstrated this way; calling the functions
directly in a single test thread, like the rest of the suite does,
wouldn't exercise the actual concurrency at all.
"""
import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.fixture
def running_server(make_proxy):
    """Starts a real ThreadingHTTPServer for a freshly-made proxy module
    on an OS-assigned free port, and tears it down after the test. Yields
    (proxy_module, base_url)."""
    def _start(**env_overrides):
        p = make_proxy(**env_overrides)
        server = p.http.server.ThreadingHTTPServer(("127.0.0.1", 0), p.AbuseIPDBHandler)
        server.daemon_threads = True
        server.request_queue_size = 128  # match main()'s production setting
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        _start.servers.append(server)
        return p, f"http://127.0.0.1:{port}"

    _start.servers = []
    yield _start
    for server in _start.servers:
        server.shutdown()
        server.server_close()


def _post(base_url, ip, categories="15", comment="test"):
    body = json.dumps({"ip": ip, "categories": categories, "comment": comment}).encode("utf-8")
    req = urllib.request.Request(base_url + "/", data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    # A couple of retries on a raw connection reset: under a burst of ~25
    # brand-new concurrent TCP connections, an occasional client-side
    # ConnectionResetError during accept()/handshake is normal socket
    # behavior under load, not a sign of a server bug — the request that
    # got reset is retried as a fresh connection, same as a real client
    # (or CrowdSec itself) would on a transient network hiccup.
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except ConnectionResetError as e:
            last_error = e
            time.sleep(0.05 * (attempt + 1))
    raise last_error


def test_concurrent_identical_ip_requests_dedup_correctly(running_server):
    p, base_url = running_server()

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: _post(base_url, "203.0.113.50"), range(20)))

    assert all(status == 200 for status, _ in results)

    cache = p.load_cache()
    assert list(cache["reports"].keys()) == ["203.0.113.50"]

    with p.metrics_lock:
        suppressed = p.metrics.get("reports_suppressed_total", 0)
    # exactly one of the 20 concurrent identical alerts should have "won"
    # the dedup race; every other one must have been suppressed, not
    # silently dropped or double-sent
    assert suppressed == 19


def test_concurrent_different_ip_requests_all_processed(running_server):
    p, base_url = running_server()
    ips = [f"203.0.{i}.1" for i in range(25)]

    with ThreadPoolExecutor(max_workers=25) as pool:
        results = list(pool.map(lambda ip: _post(base_url, ip), ips))

    assert all(status == 200 for status, _ in results)

    cache = p.load_cache()
    assert set(cache["reports"].keys()) == set(ips)


def test_slow_whitelist_check_does_not_block_other_requests(running_server):
    p, base_url = running_server(ABUSEIPDB_SKIP_WHITELISTED="true")

    def slow_is_whitelisted(ip):
        if ip == "203.0.113.99":
            time.sleep(1.5)
        return False

    p.is_whitelisted = slow_is_whitelisted

    results = {}

    def timed_post(ip):
        start = time.monotonic()
        status, _ = _post(base_url, ip)
        results[ip] = (status, time.monotonic() - start)

    with ThreadPoolExecutor(max_workers=6) as pool:
        pool.map(timed_post, ["203.0.113.99", "203.0.113.1", "203.0.113.2", "203.0.113.3"])

    assert results["203.0.113.99"][0] == 200
    assert results["203.0.113.99"][1] >= 1.5

    # the whole point of ThreadingHTTPServer: these must NOT have waited
    # behind the slow one — comfortably under the 1.5s the slow request
    # took, even with scheduling slack
    for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        assert results[ip][0] == 200
        assert results[ip][1] < 1.0, f"{ip} took {results[ip][1]}s — looks like it was blocked"


def test_server_survives_malformed_concurrent_requests(running_server):
    """A burst of garbage bodies must all get clean 500s, not take down
    other in-flight requests or the server itself."""
    p, base_url = running_server()

    def bad_post(_):
        req = urllib.request.Request(base_url + "/", data=b"not json", method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            return None
        except urllib.error.HTTPError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(pool.map(bad_post, range(10)))

    assert all(c == 500 for c in codes)

    # server must still be healthy afterwards
    status, _ = _post(base_url, "203.0.113.200")
    assert status == 200
