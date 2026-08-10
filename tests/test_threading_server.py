"""
Integration tests that actually spin up the real ThreadingHTTPServer and
fire concurrent HTTP requests at it — the class of race conditions fixed
alongside the HTTPServer -> ThreadingHTTPServer switch (dedup correctness
under real concurrency, the whitelist-check-blocks-everyone-else
limitation) can only be demonstrated this way; calling the functions
directly in a single test thread, like the rest of the suite does,
wouldn't exercise the actual concurrency at all.

The `running_server` fixture used throughout lives in conftest.py (shared
with tests/test_ipv6.py's end-to-end cases).
"""
import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest


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
        results = list(pool.map(lambda _: _post(base_url, "1.2.3.50"), range(20)))

    assert all(status == 200 for status, _ in results)

    cache = p.load_cache()
    assert list(cache["reports"].keys()) == ["1.2.3.50"]

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
        if ip == "1.2.3.99":
            time.sleep(1.5)
        return False

    p.is_whitelisted = slow_is_whitelisted

    results = {}

    def timed_post(ip):
        start = time.monotonic()
        status, _ = _post(base_url, ip)
        results[ip] = (status, time.monotonic() - start)

    with ThreadPoolExecutor(max_workers=6) as pool:
        pool.map(timed_post, ["1.2.3.99", "1.2.3.1", "1.2.3.2", "1.2.3.3"])

    assert results["1.2.3.99"][0] == 200
    assert results["1.2.3.99"][1] >= 1.5

    # the whole point of ThreadingHTTPServer: these must NOT have waited
    # behind the slow one — comfortably under the 1.5s the slow request
    # took, even with scheduling slack
    for ip in ("1.2.3.1", "1.2.3.2", "1.2.3.3"):
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
    status, _ = _post(base_url, "1.2.3.200")
    assert status == 200


def test_malformed_content_length_header_gets_a_clean_500(running_server):
    """Regression test: int(Content-Length) used to run outside the
    try/except, so a garbage header value (as opposed to a garbage body,
    which was already handled) would raise unhandled instead of getting
    the same clean 500 response every other malformed-input case gets."""
    p, base_url = running_server()
    port = int(base_url.rsplit(":", 1)[1])

    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("POST", "/")
    conn.putheader("Content-Length", "not-a-number")
    conn.endheaders()
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()

    assert status == 500

    # server must still be healthy afterwards
    status2, _ = _post(base_url, "1.2.3.201")
    assert status2 == 200


def test_max_concurrent_requests_rejects_with_503_over_the_limit(running_server):
    p, base_url = running_server(ABUSEIPDB_MAX_CONCURRENT_REQUESTS="3")

    # hold the semaphore open with slow in-flight requests, then confirm
    # a request over the limit gets a clean 503 instead of queuing forever
    release_event = threading.Event()
    original_whitelisted = p.is_whitelisted

    def blocking_check(ip):
        release_event.wait(timeout=5)
        return False

    p.SKIP_WHITELISTED = True
    p.is_whitelisted = blocking_check

    def slow_post(i):
        req = urllib.request.Request(
            base_url + "/", method="POST",
            data=json.dumps({"ip": f"203.0.200.{i}", "categories": "15", "comment": "x"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(slow_post, i) for i in range(3)]
        time.sleep(0.3)  # let the first 3 actually occupy the semaphore
        overflow_status = None
        try:
            overflow_status, _ = _post(base_url, "203.0.200.99")
        except urllib.error.HTTPError as e:
            overflow_status = e.code
        finally:
            release_event.set()
        held_statuses = [f.result() for f in futures]

    assert overflow_status == 503
    assert all(s == 200 for s in held_statuses)


def test_max_concurrent_requests_zero_disables_the_limit(running_server):
    p, base_url = running_server(ABUSEIPDB_MAX_CONCURRENT_REQUESTS="0")
    assert p._request_semaphore is None

    with ThreadPoolExecutor(max_workers=25) as pool:
        results = list(pool.map(lambda i: _post(base_url, f"203.0.201.{i}"), range(25)))

    assert all(status == 200 for status, _ in results)
