"""get_severity(): category string -> internal 1-3 severity score."""


def test_single_low_category(proxy):
    assert proxy.get_severity("14") == 1  # Port Scan


def test_single_high_category(proxy):
    assert proxy.get_severity("15") == 3  # Hacking


def test_takes_the_max_of_multiple_categories(proxy):
    # 14 (Port Scan, low=1) escalating to 16 (SQL Injection, high=3)
    assert proxy.get_severity("14,16") == 3


def test_order_does_not_matter(proxy):
    assert proxy.get_severity("16,14") == proxy.get_severity("14,16")


def test_unknown_category_defaults_to_low(proxy):
    assert proxy.get_severity("9999") == 1


def test_handles_whitespace_around_categories(proxy):
    assert proxy.get_severity(" 15 , 14 ") == 3


def test_empty_string_defaults_to_low(proxy):
    assert proxy.get_severity("") == 1


def test_all_23_categories_are_mapped(proxy):
    # Regression guard for the v1.2.0 change that added full category
    # coverage — every official AbuseIPDB category ID (1-23) must resolve
    # to a valid 1-3 severity, not silently fall back to the default.
    for cat_id in range(1, 24):
        assert proxy.SEVERITY_MAP[str(cat_id)] in (1, 2, 3)
