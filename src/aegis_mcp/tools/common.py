"""Reusable validated field types for tool signatures."""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints

CveId = Annotated[
    str,
    StringConstraints(pattern=r"^(?i)CVE-\d{4}-\d{4,7}$", min_length=9, max_length=32, strip_whitespace=True),
]
IncidentId = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$", min_length=3, max_length=64, strip_whitespace=True),
]
Keyword = Annotated[str, StringConstraints(min_length=2, max_length=128, strip_whitespace=True)]
Title = Annotated[str, StringConstraints(min_length=3, max_length=256, strip_whitespace=True)]
AssetName = Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=True)]
