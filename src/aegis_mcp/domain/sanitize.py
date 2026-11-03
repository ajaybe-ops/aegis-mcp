"""Input validation and prompt-injection hardening.

External vulnerability feeds are untrusted input. This module performs two distinct
jobs:

1. Strictly validate caller-controlled identifiers before they touch URLs, SQL, or
   logs (allowlist patterns, length caps).
2. Sanitize third-party text before it is placed in structured tool output or
   prompts (remove control characters, ANSI escapes, bidi overrides; bound size).

Sanitization reduces injection and log-spoofing surface. It does **not** make
untrusted text trustworthy, so every consumer must still treat it as data.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

from .errors import InputValidationError

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
INCIDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,127}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+~\-]{0,63}$")
ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@ \-]{0,127}$")

_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069\u200e\u200f]")
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200d\u2060\ufeff]")
_SPACE_RE = re.compile(r"[ \t\f\v]+")
_NEWLINE_RE = re.compile(r"\n{3,}")


def clean_untrusted(value: str, *, max_length: int = 4_000) -> str:
    """Normalize and bound third-party text without destroying meaning."""
    if not value:
        return ""
    text = unicodedata.normalize("NFKC", value)
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _SPACE_RE.sub(" ", text)
    text = _NEWLINE_RE.sub("\n\n", text).strip()
    marker = " [truncated]"
    if len(text) > max_length:
        text = text[: max_length - len(marker)].rstrip() + marker
    return text


def normalize_cve_id(value: str) -> str:
    normalized = value.strip().upper()
    if not CVE_RE.match(normalized):
        raise InputValidationError("CVE identifiers must match CVE-YYYY-NNNN (4-7 digits)")
    return normalized


def validate_incident_id(value: str) -> str:
    normalized = value.strip()
    if not INCIDENT_RE.match(normalized):
        raise InputValidationError("incident_id must be 3-64 characters of letters, digits, '_' or '-'")
    return normalized


def validate_package_name(value: str) -> str:
    normalized = value.strip()
    if not PACKAGE_RE.match(normalized) or ".." in normalized:
        raise InputValidationError("package name contains unsupported characters or path traversal")
    return normalized


def validate_version(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not VERSION_RE.match(normalized):
        raise InputValidationError("package version contains unsupported characters")
    return normalized


def validate_asset(value: str) -> str:
    normalized = clean_untrusted(value, max_length=128).strip()
    if not ASSET_RE.match(normalized):
        raise InputValidationError("asset name must be 1-128 characters of letters, digits, or ._:/@-")
    return normalized


def safe_url(value: str) -> str | None:
    """Return a normalized http(s) URL, or None for anything unsafe."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    if parts.username or parts.password:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def cap_list(items: list[str], *, limit: int) -> list[str]:
    return items[:limit]
