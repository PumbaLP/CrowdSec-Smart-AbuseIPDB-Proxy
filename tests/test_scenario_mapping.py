"""
Cross-checks SCENARIO_CATEGORY_RULES in abuseipdb_proxy.py against the
actual Go template in abuseipdb.yaml, so the two can't silently drift
apart — --reconcile only categorizes as accurately as this list matches
what CrowdSec's notification plugin itself would have done.
"""
import re
from pathlib import Path

import pytest


YAML_PATH = Path(__file__).parent.parent / "abuseipdb.yaml"


def _parse_yaml_template_rules():
    """Extracts (substring, categories) pairs from abuseipdb.yaml's Go
    template, in the same order they're evaluated in (first match wins).
    Deliberately a narrow regex-based parser, not a real Go template
    engine — it only needs to understand the specific
    `contains "x" $scenario` / `or (...) (...)` shape this template uses."""
    text = YAML_PATH.read_text(encoding="utf-8")

    # Pull out just the `format:` block's template lines
    lines = text.splitlines()
    template_lines = [l for l in lines if "contains" in l or re.search(r"{{-\s*else\s*-}}", l)]

    rules = []
    default = None
    for line in template_lines:
        conditions = re.findall(r'contains\s+"([^"]+)"\s+\$scenario', line)
        # value is whatever trails the `-}}` up to the next `{{-` (or end of line)
        value_match = re.search(r"-}}\s*([0-9,]+)\s*(?:{{-|$)", line)
        value = value_match.group(1).strip() if value_match else None

        if conditions and value:
            for substring in conditions:
                rules.append((substring, value))
        elif not conditions and value:
            default = value  # the final `{{- else -}} 15 {{- end -}}` line

    return rules, default


def test_yaml_template_is_parseable_at_all():
    """Sanity check on the parser itself — if this fails, the regex
    above needs updating for a template shape change, not the rules."""
    rules, default = _parse_yaml_template_rules()
    assert len(rules) > 20
    assert default == "15"


def test_python_rules_match_yaml_template_exactly():
    import abuseipdb_proxy as proxy

    yaml_rules, yaml_default = _parse_yaml_template_rules()

    assert proxy.SCENARIO_CATEGORY_RULES == yaml_rules, (
        "SCENARIO_CATEGORY_RULES in abuseipdb_proxy.py has drifted from "
        "abuseipdb.yaml's template. Whichever one you just edited, update "
        "the other to match — --reconcile's categorization depends on "
        "them staying identical."
    )
    assert proxy.SCENARIO_CATEGORY_DEFAULT == yaml_default


@pytest.mark.parametrize("scenario,expected", [
    ("crowdsecurity/ssh-bf", "18,22"),
    ("crowdsecurity/telnet-bf", "18,23"),
    ("crowdsecurity/vsftpd-bf", "5,18"),
    ("crowdsecurity/mysql-bf", "18"),
    ("crowdsecurity/dovecot-bf", "18"),
    ("crowdsecurity/http-crawl-non_statics", "19"),  # "crawl" is checked before "http"
    ("crowdsecurity/http-sqli-probing", "16,21"),    # "sqli" before "http"
    ("crowdsecurity/http-xss-probing", "21"),
    ("crowdsecurity/http-path-traversal-probing", "21"),
    ("crowdsecurity/http-open-proxy", "9"),
    ("crowdsecurity/http-backdoors-attempts", "15,20"),
    ("crowdsecurity/http-bad-user-agent", "19"),
    ("crowdsecurity/http-sensitive-files", "21"),
    ("crowdsecurity/http-probing", "21"),
    ("crowdsecurity/http-generic-bf", "18"),          # "bruteforce"/"-bf" before "http"
    ("crowdsecurity/CVE-2022-12345", "15,21"),
    ("crowdsecurity/http-generic", "21"),
    ("some-unknown-exploit-attempt", "15,21"),
    ("totally-unrecognized-scenario", "15"),          # default
])
def test_categories_for_scenario_matches_expected(scenario, expected):
    import abuseipdb_proxy as proxy
    assert proxy.categories_for_scenario(scenario) == expected


def test_categories_for_scenario_is_case_insensitive():
    import abuseipdb_proxy as proxy
    assert proxy.categories_for_scenario("CrowdSecurity/SSH-BF") == "18,22"


def test_categories_for_scenario_none_for_empty_input():
    import abuseipdb_proxy as proxy
    assert proxy.categories_for_scenario("") is None
    assert proxy.categories_for_scenario(None) is None
