"""log(): plain-text (default) vs. structured JSON (ABUSEIPDB_LOG_FORMAT=json) output."""
import json

import pytest


def test_text_format_is_the_default(proxy, capsys):
    proxy.log("something happened")
    captured = capsys.readouterr()
    assert captured.err == "[abuseipdb-proxy] something happened\n"


def test_text_format_ignores_extra_fields(proxy, capsys):
    # Text mode is the plain legacy format — structured fields are only
    # surfaced in JSON mode, not appended to the text line.
    proxy.log("something happened", level="warning", ip="1.2.3.4", attempts=3)
    captured = capsys.readouterr()
    assert captured.err == "[abuseipdb-proxy] something happened\n"


def test_json_format_produces_one_parseable_line(make_proxy, capsys):
    p = make_proxy(ABUSEIPDB_LOG_FORMAT="json")
    p.log("something happened")
    captured = capsys.readouterr()

    lines = captured.err.strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["message"] == "something happened"
    assert record["level"] == "info"
    assert "timestamp" in record


def test_json_format_includes_extra_fields(make_proxy, capsys):
    p = make_proxy(ABUSEIPDB_LOG_FORMAT="json")
    p.log("report failed", level="warning", ip="1.2.3.4", http_status=429)
    record = json.loads(capsys.readouterr().err.strip())

    assert record["level"] == "warning"
    assert record["ip"] == "1.2.3.4"
    assert record["http_status"] == 429


def test_json_timestamp_is_iso8601_utc(make_proxy, capsys):
    from datetime import datetime

    p = make_proxy(ABUSEIPDB_LOG_FORMAT="json")
    p.log("hi")
    record = json.loads(capsys.readouterr().err.strip())

    # Must parse cleanly and carry explicit UTC offset info.
    parsed = datetime.fromisoformat(record["timestamp"])
    assert parsed.tzinfo is not None


@pytest.mark.parametrize("value", ["JSON", "Json", " json "])
def test_log_format_env_var_is_normalized(make_proxy, capsys, value):
    p = make_proxy(ABUSEIPDB_LOG_FORMAT=value)
    p.log("hi")
    captured = capsys.readouterr()
    # Should NOT fall back to plain text for any casing/whitespace variant.
    json.loads(captured.err.strip())


def test_unknown_log_format_falls_back_to_text(make_proxy, capsys):
    p = make_proxy(ABUSEIPDB_LOG_FORMAT="xml")
    p.log("hi")
    captured = capsys.readouterr()
    assert captured.err == "[abuseipdb-proxy] hi\n"


def test_real_call_sites_actually_use_structured_fields(make_proxy, capsys, tmp_path):
    # Spot-check a real call site (not just the log() helper in
    # isolation) to make sure the refactor actually wired fields through
    # rather than just adding a helper nobody calls with extras. The
    # JSON-to-SQLite migration path logs synchronously, so no thread
    # test-double juggling needed here.
    import json as jsonlib

    db_path = tmp_path / "cache.db"
    (tmp_path / "cache.json").write_text(jsonlib.dumps({"reports": {}, "pending": {}, "retry_queue": {}}))

    p = make_proxy(ABUSEIPDB_LOG_FORMAT="json", ABUSEIPDB_CACHE_BACKEND="sqlite",
                    ABUSEIPDB_CACHE_FILE=str(db_path))
    p.load_cache()  # triggers the migration, which logs

    lines = [line for line in capsys.readouterr().err.strip().splitlines() if line]
    assert lines, "expected at least one log line from the migration"
    records = [json.loads(line) for line in lines]  # every line must be valid JSON
    assert any("entries" in r for r in records)  # the "Migration complete" line carries a field
