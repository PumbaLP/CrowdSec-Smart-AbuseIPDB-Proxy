"""_summary_loop() -- the periodic (every ABUSEIPDB_SUMMARY_INTERVAL
seconds) summary log line, logged instead of a line per event to keep
the journal readable under high-volume traffic. Silent when nothing
happened since the last summary."""
import pytest


class _StopLoop(Exception):
    """Raised from a patched time.sleep() to break out of _summary_loop()'s
    `while True` after a controlled number of iterations, since the real
    function never returns on its own."""


def _run_n_iterations(proxy, monkeypatch, n):
    calls = {"n": 0}

    def fake_sleep(seconds):
        calls["n"] += 1
        if calls["n"] > n:
            raise _StopLoop()

    monkeypatch.setattr(proxy.time, "sleep", fake_sleep)
    with pytest.raises(_StopLoop):
        proxy._summary_loop()


def test_silent_when_nothing_happened_since_last_summary(proxy, monkeypatch, capsys):
    _run_n_iterations(proxy, monkeypatch, 1)
    assert capsys.readouterr().err == ""


def test_logs_a_summary_line_when_something_happened(proxy, monkeypatch, capsys):
    proxy.metrics["reports_sent_total"] = 3
    proxy.metrics["reports_suppressed_total"] = 1

    _run_n_iterations(proxy, monkeypatch, 1)

    captured = capsys.readouterr().err
    assert "3 sent" in captured
    assert "1 suppressed" in captured


def test_only_reports_the_delta_since_the_last_iteration_not_the_running_total(proxy, monkeypatch, capsys):
    # last_snapshot lives inside a single _summary_loop() call (reset to
    # zero on every fresh invocation), so this has to drive multiple
    # iterations of the *same* call via the sleep-mock itself, not two
    # separate _summary_loop() calls.
    outputs = []
    call_count = {"n": 0}

    def fake_sleep(seconds):
        call_count["n"] += 1
        # By the time sleep is called again, the previous iteration's
        # body (if any) has already run and logged its line -- capture
        # whatever accumulated in the meantime before this iteration
        # changes the metrics further.
        outputs.append(capsys.readouterr().err)
        if call_count["n"] == 1:
            proxy.metrics["reports_sent_total"] = 5
        elif call_count["n"] == 2:
            proxy.metrics["reports_sent_total"] = 7  # +2 since the previous iteration
        else:
            raise _StopLoop()

    monkeypatch.setattr(proxy.time, "sleep", fake_sleep)
    with pytest.raises(_StopLoop):
        proxy._summary_loop()

    # outputs[0]: nothing logged yet (before iteration 1's body ran)
    # outputs[1]: iteration 1's line (the full 5, first activity seen)
    # outputs[2]: iteration 2's line (the delta: +2, not the running 7)
    assert outputs[0] == ""
    assert "5 sent" in outputs[1]
    assert "2 sent" in outputs[2]
