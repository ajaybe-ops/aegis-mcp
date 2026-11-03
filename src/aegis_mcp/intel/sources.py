"""Authoritative source catalog exposed to agents and operators."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    name: str
    title: str
    endpoint: str
    license: str
    attribution: str
    cached_seconds: int
    trust: str = "untrusted_external"


SOURCES: tuple[Source, ...] = (
    Source(
        name="nvd",
        title="NIST National Vulnerability Database API 2.0",
        endpoint="https://services.nvd.nist.gov/rest/json/cves/2.0",
        license="Public domain (U.S. Government work)",
        attribution="NIST NVD",
        cached_seconds=300,
    ),
    Source(
        name="epss",
        title="FIRST Exploit Prediction Scoring System",
        endpoint="https://api.first.org/data/v1/epss",
        license="CC BY 4.0 / FIRST terms",
        attribution="FIRST EPSS",
        cached_seconds=300,
    ),
    Source(
        name="kev",
        title="CISA Known Exploited Vulnerabilities catalog",
        endpoint="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        license="Public domain (U.S. Government work)",
        attribution="CISA KEV",
        cached_seconds=3_600,
    ),
    Source(
        name="osv",
        title="Google Open Source Vulnerabilities",
        endpoint="https://api.osv.dev/v1/query",
        license="Apache-2.0 / OSV data licenses per advisory",
        attribution="OSV.dev",
        cached_seconds=300,
    ),
)

ALLOWED_HOSTS = frozenset(
    {
        "services.nvd.nist.gov",
        "api.first.org",
        "www.cisa.gov",
        "api.osv.dev",
    }
)


def catalog_document() -> dict[str, object]:
    return {
        "schema_version": "1",
        "trust_model": (
            "All feed content is untrusted external data. It is sanitized, bounded, and never executed. "
            "Only identifiers are used to build fixed upstream URLs."
        ),
        "sources": [
            {
                "name": source.name,
                "title": source.title,
                "endpoint": source.endpoint,
                "license": source.license,
                "attribution": source.attribution,
                "cached_seconds": source.cached_seconds,
                "trust": source.trust,
            }
            for source in SOURCES
        ],
    }
