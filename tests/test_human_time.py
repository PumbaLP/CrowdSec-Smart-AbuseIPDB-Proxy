"""_human_ago() / _human_in() -- human-readable relative time formatting
used by --stats/--doctor output."""
import pytest


@pytest.mark.parametrize("delta,expected", [
    (2, "just now"),
    (30, "30s ago"),
    (90, "1m ago"),
    (7200, "2h ago"),
    (172800, "2d ago"),
])
def test_human_ago_buckets(proxy, delta, expected):
    now = 1_000_000
    assert proxy._human_ago(now - delta, now=now) == expected


def test_human_in_due_now(proxy):
    now = 1_000_000
    assert proxy._human_in(now - 5, now=now) == "due now"
    assert proxy._human_in(now, now=now) == "due now"


def test_human_in_minutes_and_seconds(proxy):
    now = 1_000_000
    assert proxy._human_in(now + 125, now=now) == "in 2m 5s"


def test_human_in_hours_and_minutes(proxy):
    now = 1_000_000
    assert proxy._human_in(now + 7500, now=now) == "in 2h 5m"
