"""format_startup_banner()/print_startup_banner(): the boxed startup summary."""


def test_banner_includes_version(proxy):
    banner = proxy.format_startup_banner()
    assert proxy.VERSION in banner


def test_banner_includes_mode(make_proxy):
    dry = make_proxy(ABUSEIPDB_DRY_RUN="true")
    assert "dry-run" in dry.format_startup_banner()

    live = make_proxy(ABUSEIPDB_DRY_RUN="false")
    assert "live" in live.format_startup_banner()


def test_banner_includes_cache_backend_and_file(make_proxy, tmp_path):
    p = make_proxy(ABUSEIPDB_CACHE_BACKEND="sqlite", ABUSEIPDB_CACHE_FILE=str(tmp_path / "cache.db"))
    banner = p.format_startup_banner()
    assert "sqlite" in banner
    assert str(tmp_path / "cache.db") in banner


def test_banner_includes_listen_address_and_port(make_proxy):
    p = make_proxy(ABUSEIPDB_LISTEN_ADDRESS="0.0.0.0", ABUSEIPDB_PROXY_PORT="12345")
    banner = p.format_startup_banner()
    assert "0.0.0.0:12345" in banner


def test_banner_shows_no_backends_configured_by_default(proxy):
    assert "none configured" in proxy.format_startup_banner()


def test_banner_lists_configured_backends(make_proxy):
    p = make_proxy(ABUSEIPDB_GOTIFY_URL="https://gotify.example.com", ABUSEIPDB_GOTIFY_TOKEN="t",
                    ABUSEIPDB_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/x")
    banner = p.format_startup_banner()
    assert "Gotify" in banner
    assert "Discord" in banner
    assert "none configured" not in banner


def test_banner_includes_repo_url(proxy):
    assert "github.com/PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy" in proxy.format_startup_banner()


def test_banner_is_a_well_formed_box(proxy):
    lines = proxy.format_startup_banner().splitlines()
    assert lines[0].startswith("/") and lines[0].endswith("\\")
    assert lines[-1].startswith("\\") and lines[-1].endswith("/")
    # every line has consistent width (a ragged box would look broken)
    widths = {len(line) for line in lines}
    assert len(widths) == 1


def test_print_startup_banner_writes_to_stderr_in_text_mode(proxy, capsys):
    proxy.print_startup_banner()
    captured = capsys.readouterr()
    assert proxy.VERSION in captured.err
    assert captured.out == ""


def test_print_startup_banner_is_silent_in_json_mode(make_proxy, capsys):
    p = make_proxy(ABUSEIPDB_LOG_FORMAT="json")
    p.print_startup_banner()
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_only_shown_for_the_actual_service_boot_not_one_off_cli_flags(tmp_path):
    # --version, --stats, etc. are scripting-friendly one-shot commands —
    # a decorative banner on stderr would be harmless to parsing (stdout
    # stays clean either way) but is still just noise nobody asked for.
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[1] / "abuseipdb_proxy.py"
    env = {k: v for k, v in os.environ.items() if not k.startswith("ABUSEIPDB_")}
    env["ABUSEIPDB_API_KEY"] = "test-key"
    env["ABUSEIPDB_CACHE_FILE"] = str(tmp_path / "cache.db")

    result = subprocess.run([sys.executable, str(script), "--version"],
                             capture_output=True, text=True, timeout=10, env=env)
    assert "/---" not in result.stderr
    assert "/---" not in result.stdout
