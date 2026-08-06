"""
Tests for the Docker/Podman-secrets-style `{VAR}_FILE` convention
(_get_secret()), used for every secret-like config value: API_KEY,
API_KEY_FALLBACK, CROWDSEC_BOUNCER_KEY, SHARED_SECRET, and all the
notification backend tokens/webhook URLs.
"""
import pytest


def test_plain_env_var_used_when_no_file_configured(proxy, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET", "plain-value")
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET") == "plain-value"


def test_default_used_when_neither_is_set(proxy, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_TEST_SECRET", raising=False)
    monkeypatch.delenv("ABUSEIPDB_TEST_SECRET_FILE", raising=False)
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET", "fallback") == "fallback"
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET") == ""


def test_file_variant_is_read(proxy, monkeypatch, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("from-file-value")
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET_FILE", str(secret_file))
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET") == "from-file-value"


def test_file_content_is_stripped(proxy, monkeypatch, tmp_path):
    # secrets files routinely have a trailing newline (echo, printf, most
    # editors) — that must never end up as part of the actual value
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("from-file-value\n")
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET_FILE", str(secret_file))
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET") == "from-file-value"


def test_file_wins_over_plain_env_var_when_both_set(proxy, monkeypatch, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-value")
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET", "plain-value")
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET_FILE", str(secret_file))
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET") == "file-value"


def test_missing_file_falls_back_to_plain_env_var_not_fatal(proxy, monkeypatch, capsys):
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET", "plain-value")
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET_FILE", "/nonexistent/path/secret.txt")
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET") == "plain-value"
    assert "Warning: could not read ABUSEIPDB_TEST_SECRET_FILE" in capsys.readouterr().err


def test_missing_file_and_no_plain_var_falls_back_to_default(proxy, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_TEST_SECRET", raising=False)
    monkeypatch.setenv("ABUSEIPDB_TEST_SECRET_FILE", "/nonexistent/path/secret.txt")
    assert proxy._get_secret("ABUSEIPDB_TEST_SECRET", "fallback") == "fallback"


# --- End-to-end: the API key itself, which is resolved before log()
# exists at module-import time — the one case _get_secret() has to get
# right without being able to lean on the module's own logger. ---------

def test_api_key_resolved_from_file(make_proxy, tmp_path):
    key_file = tmp_path / "api_key.txt"
    key_file.write_text("key-from-file\n")
    p = make_proxy(ABUSEIPDB_API_KEY="", ABUSEIPDB_API_KEY_FILE=str(key_file))
    assert p.API_KEY == "key-from-file"


def test_api_key_file_wins_over_plain_var(make_proxy, tmp_path):
    key_file = tmp_path / "api_key.txt"
    key_file.write_text("key-from-file")
    p = make_proxy(ABUSEIPDB_API_KEY="key-from-env", ABUSEIPDB_API_KEY_FILE=str(key_file))
    assert p.API_KEY == "key-from-file"


def test_bouncer_key_resolved_from_file(make_proxy, tmp_path):
    key_file = tmp_path / "bouncer_key.txt"
    key_file.write_text("bouncer-key-from-file")
    p = make_proxy(ABUSEIPDB_CROWDSEC_BOUNCER_KEY_FILE=str(key_file))
    assert p.CROWDSEC_BOUNCER_KEY == "bouncer-key-from-file"


def test_shared_secret_resolved_from_file(make_proxy, tmp_path):
    secret_file = tmp_path / "shared_secret.txt"
    secret_file.write_text("shared-secret-from-file")
    p = make_proxy(ABUSEIPDB_SHARED_SECRET_FILE=str(secret_file))
    assert p.is_shared_secret_valid("shared-secret-from-file") is True
    assert p.is_shared_secret_valid("wrong") is False
