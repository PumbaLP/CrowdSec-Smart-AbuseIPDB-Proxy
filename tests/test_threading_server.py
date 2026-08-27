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


def test_malformed_content_length_header_gets_a_clean_400(running_server):
    """Regression test: int(Content-Length) used to run outside the
    try/except, so a garbage header value (as opposed to a garbage body,
    which was already handled) would raise unhandled instead of getting
    a clean response. Now explicitly caught and treated as invalid
    (same path as a negative Content-Length -- see the dedicated hang
    regression test below), returning a clean 400 rather than the
    generic 500 every other malformed-*body* case still gets."""
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

    assert status == 400

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


def test_real_concurrent_escalation_and_retry_does_not_corrupt_retry_queue(running_server):
    """
    Real (not simulated) concurrency stress test for the retry-chain-race
    fix (_cancel_active_retry_chain): a first report for an ip fails and
    starts an actual (short-delay) retry backoff, while genuine concurrent
    escalations for the SAME ip keep arriving from real threads hitting
    the real HTTP server, each capable of starting its own send_with_retry
    thread. Runs several rounds to shake out any timing-dependent
    corruption that a single run might miss.
    """
    p, base_url = running_server(ABUSEIPDB_RETRY_DELAY="1", ABUSEIPDB_REPORT_WINDOW="0")

    call_count = {"n": 0}
    call_lock = threading.Lock()

    def flaky_send(ip, categories, comment):
        with call_lock:
            call_count["n"] += 1
            n = call_count["n"]
        # Roughly half fail, half succeed -- deliberately unpredictable
        # which chain "wins", the point is that the cache never ends up
        # in a corrupted/inconsistent state no matter which one does.
        return (n % 2 == 0), None

    p.send_report_api = flaky_send

    for round_n in range(10):
        ip = f"198.51.100.{round_n}"
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(
                lambda i: _post(base_url, ip, categories="18" if i % 2 else "14",
                                 comment=f"round{round_n}-{i}"),
                range(8),
            ))
        assert all(status == 200 for status, _ in results)

    time.sleep(2.5)  # let any real retry timers (1s delay) fire

    # The cache must remain internally consistent no matter how the races
    # above resolved: every ip that has a "reports" row must NOT also be
    # stuck with a retry_queue row referencing a chain that will never
    # fire again (the corrupted state the race could previously cause),
    # and vice versa there must be no orphaned retry_queue row for an ip
    # with no corresponding report and no active in-memory timer for it.
    cache = p.load_cache()
    for ip, retry_info in cache["retry_queue"].items():
        assert ip in p.retry_timers, (
            f"{ip} has a persisted retry_queue row but no active in-memory "
            f"timer -- it will never fire, exactly the corruption "
            f"_cancel_active_retry_chain is meant to prevent"
        )


def test_non_string_ip_field_is_rejected_not_silently_coerced(running_server):
    """
    Regression test: ipaddress.ip_address() silently accepts an int
    (interpreting it as a packed address) instead of raising, so an "ip"
    field that's a JSON number rather than a string used to sail straight
    through is_ignored_ip()/is_whitelisted() and get treated as a real
    address. A malformed/malicious POST with a numeric "ip" must now be
    a no-op (still 200 OK, matching how a missing "ip" is already
    handled) rather than silently generating a report for whatever
    address that integer happens to decode to.
    """
    p, base_url = running_server()

    body = json.dumps({"ip": 16909060, "categories": "15", "comment": "x"}).encode("utf-8")
    req = urllib.request.Request(base_url + "/", data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        status = resp.status

    assert status == 200
    # 16909060 decodes to 1.2.3.4 -- confirm THAT never got reported either.
    assert "1.2.3.4" not in p.load_cache()["reports"]
    assert p.load_cache()["reports"] == {}


def test_health_endpoint_reports_oldest_entry_ages(running_server):
    p, base_url = running_server(ABUSEIPDB_ENABLE_HEALTH="true")
    p._sqlite_upsert_pending("1.2.3.4", due_time=999999999999, severity=1, categories="14", comment="x")

    with urllib.request.urlopen(base_url + "/health", timeout=5) as resp:
        data = json.loads(resp.read())

    assert data["oldest_pending_escalation_age_seconds"] is not None
    assert data["oldest_pending_escalation_age_seconds"] < 20
    assert data["oldest_pending_retry_age_seconds"] is None


def test_negative_content_length_does_not_hang_the_worker_thread(running_server):
    """
    Regression test for a real, reproducible hang: BufferedReader.read(n)
    for n < 0 means "read until EOF", which on a live socket blocks until
    the *client* closes the connection. A "Content-Length: -1" header
    used to reach rfile.read(-1) directly -- a client that just keeps the
    connection open (accidentally or deliberately) hung that worker
    thread forever, permanently consuming one MAX_CONCURRENT_REQUESTS
    slot per such request (the semaphore is only released in do_POST()'s
    `finally`, which never runs for a thread that never returns).
    Confirmed first against the unfixed code with a real socket before
    this was written: a 5s recv() timed out with no response at all.
    """
    import socket
    p, base_url = running_server()
    port = int(base_url.rsplit(":", 1)[1])

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            b"Content-Length: -1\r\n\r\n"
        )
        # Deliberately NOT closing the connection here -- that's exactly
        # the condition that used to cause the hang (rfile.read(-1)
        # waiting for EOF that a well-behaved client would eventually
        # provide by closing, but nothing forces a client to).
        response = s.recv(4096)
    finally:
        s.close()

    assert b"400" in response.split(b"\r\n", 1)[0]


def test_server_remains_responsive_after_a_negative_content_length_request(running_server):
    # Belt-and-suspenders: after the malformed request above, a normal
    # request must still get served promptly -- confirms the fix didn't
    # just avoid a crash while still leaking the concurrency slot some
    # other way.
    p, base_url = running_server()
    status, _ = _post(base_url, "192.0.2.1")
    assert status == 200


def test_oversized_content_length_is_rejected_without_reading_the_body(running_server):
    p, base_url = running_server()
    port = int(base_url.rsplit(":", 1)[1])

    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("POST", "/")
    conn.putheader("Content-Length", str(p.MAX_REQUEST_BODY_BYTES + 1))
    conn.endheaders()
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()

    assert status == 400
