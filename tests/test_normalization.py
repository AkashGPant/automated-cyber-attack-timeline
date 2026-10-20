from datetime import datetime

import pytest

from core.normalization import (NormalizationEngine as N, is_external_ip, is_internal_ip,
                                ip_in_networks)

INTERNAL = ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"]


@pytest.mark.parametrize("value", [
    "2026-10-18T09:00:00.000Z", "2026-10-18 09:00:00", "10/18/2026 9:00:00 AM",
    "2026-10-18T14:30:00+05:30",
])
def test_parse_timestamp_formats(value):
    assert N.parse_timestamp(value) != datetime.min


def test_parse_timestamp_tz_normalized_to_utc():
    assert N.parse_timestamp("2026-10-18T14:30:00+05:30") == datetime(2026, 10, 18, 9, 0, 0)


def test_parse_timestamp_epoch_variants():
    assert N.parse_timestamp(1_760_000_000).year == 2025
    assert N.parse_timestamp("1760000000000").year == 2025  # ms


@pytest.mark.parametrize("bad", ["", "nan", None, "not a date", "-", float("nan")])
def test_parse_timestamp_invalid(bad):
    assert N.parse_timestamp(bad) == datetime.min


def test_clean_str_and_int():
    assert N.clean_str("  x ") == "x"
    assert N.clean_str("nan") is None
    assert N.to_int("4624.0") == 4624
    assert N.to_int("0x1fffff") == 0x1fffff
    assert N.to_int("bad") is None


def test_normalize_ip():
    assert N.normalize_ip("::ffff:198.51.100.23") == "198.51.100.23"
    assert N.normalize_ip("[2001:db8::1]") == "2001:db8::1"
    assert N.normalize_ip("999.1.1.1") is None


def test_parse_hashes():
    hs = N.parse_hashes("MD5=ABC123abc123ABC123abc123ABC12345,SHA256=" + "a" * 64)
    assert hs["MD5"] == "abc123abc123abc123abc123abc12345"
    assert "SHA256" in hs


def test_decode_powershell():
    import base64
    payload = "Write-Output hello"
    enc = base64.b64encode(payload.encode("utf-16-le")).decode()
    decoded = N.decode_powershell(f"powershell -enc {enc}")
    assert decoded and "hello" in decoded


def test_internal_external_classification():
    assert is_internal_ip("10.10.20.37", INTERNAL)
    assert is_external_ip("203.0.113.45", INTERNAL)
    assert not is_external_ip("10.10.20.37", INTERNAL)
    assert not is_external_ip("127.0.0.1", INTERNAL)
    assert ip_in_networks("fc00::1", INTERNAL)
