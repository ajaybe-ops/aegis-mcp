"""Sanitization and identifier validation are prompt-injection defenses."""

from __future__ import annotations

import pytest

from aegis_mcp.domain.errors import InputValidationError
from aegis_mcp.domain.sanitize import (
    clean_untrusted,
    normalize_cve_id,
    safe_url,
    validate_asset,
    validate_incident_id,
    validate_package_name,
    validate_version,
)


def test_control_characters_and_ansi_are_removed() -> None:
    text = "safe\x1b[31mred\x00text\x07"
    assert clean_untrusted(text) == "saferedtext"


def test_bidi_and_zero_width_overrides_are_removed() -> None:
    text = "left\u202eright\u200bzero\u2066isolate\u2069"
    cleaned = clean_untrusted(text)
    assert "\u202e" not in cleaned
    assert "\u200b" not in cleaned
    assert "\u2066" not in cleaned
    assert cleaned == "leftrightzeroisolate"


def test_newlines_are_normalized_and_compacted() -> None:
    assert clean_untrusted("a\r\nb\r\n\r\n\r\nc") == "a\nb\n\nc"
    assert clean_untrusted("a\tb   c") == "a b c"


def test_long_text_is_truncated_with_marker() -> None:
    cleaned = clean_untrusted("x" * 100, max_length=40)
    assert len(cleaned) == 40
    assert cleaned.endswith("[truncated]")


def test_empty_text_is_empty() -> None:
    assert clean_untrusted("") == ""
    assert clean_untrusted(None) == ""  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("cve-2021-44228", "CVE-2021-44228"),
        ("  CVE-2021-44228  ", "CVE-2021-44228"),
        ("CVE-2024-1234567", "CVE-2024-1234567"),
    ],
)
def test_cve_normalization(raw: str, expected: str) -> None:
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "CVE-21-1", "CVE-2021-123", "GHSA-xxxx", "CVE-2021-12345678"])
def test_bad_cve_ids_are_rejected(raw: str) -> None:
    with pytest.raises(InputValidationError):
        normalize_cve_id(raw)


def test_incident_ids() -> None:
    assert validate_incident_id(" INC-2026_001 ") == "INC-2026_001"
    with pytest.raises(InputValidationError):
        validate_incident_id("x")
    with pytest.raises(InputValidationError):
        validate_incident_id("../etc/passwd")


def test_package_and_version_validation() -> None:
    assert validate_package_name("org.apache.logging.log4j:log4j-core") == "org.apache.logging.log4j:log4j-core"
    assert validate_version(" 2.14.1 ") == "2.14.1"
    assert validate_version(None) is None
    with pytest.raises(InputValidationError):
        validate_package_name("../secret")
    with pytest.raises(InputValidationError):
        validate_package_name("bad package")
    with pytest.raises(InputValidationError):
        validate_version("1.0\n2.0")


def test_asset_validation_cleans_then_validates() -> None:
    assert validate_asset("payments\u202e-api-1") == "payments-api-1"
    with pytest.raises(InputValidationError):
        validate_asset("")


def test_safe_url_allows_only_http_without_credentials() -> None:
    assert safe_url("https://example.test/a?b=1#frag") == "https://example.test/a?b=1"
    assert safe_url("javascript:alert(1)") is None
    assert safe_url("https://user:pass@example.test/") is None
    assert safe_url("https://example.test/\x00") is None
    assert safe_url("not a url") is None
