"""Intel orchestration and provider parsers, all offline and deterministic."""

from __future__ import annotations

from typing import Any

import pytest

from aegis_mcp.domain.errors import InputValidationError, NotFoundError, UpstreamError
from aegis_mcp.domain.models import AssetCriticality, Ecosystem, PackageQuery
from aegis_mcp.infra.cache import TTLCache
from aegis_mcp.infra.telemetry import configure_observability
from aegis_mcp.intel.fixtures import fixture_nvd_payload, fixture_osv_payload
from aegis_mcp.intel.service import IntelService

from .helpers import offline_settings


def _service(**overrides: Any) -> IntelService:
    settings = offline_settings(**overrides)
    return IntelService(
        settings=settings,
        http=None,
        cache=TTLCache(),
        telemetry=configure_observability(settings),
    )


class FakeHttp:
    def __init__(self, payload: Any, *, error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def request_json(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append({"method": method, "url": url, **kwargs})
        if self.error is not None:
            raise self.error
        return self.payload


async def test_lookup_known_cve() -> None:
    assessment = await _service().lookup_cve("cve-2021-44228", AssetCriticality.HIGH)
    assert assessment.cve.cve_id == "CVE-2021-44228"
    assert assessment.cve.kev is not None
    assert assessment.cve.epss is not None
    assert assessment.cve.cvss is not None
    assert assessment.risk.score == pytest.approx(95.6, abs=0.1)
    assert assessment.risk.band.value == "critical"
    assert assessment.sources
    assert all(source.fetched_at is not None for source in assessment.sources)


async def test_lookup_missing_cve() -> None:
    with pytest.raises(NotFoundError, match="CVE-1999-9999"):
        await _service().lookup_cve("CVE-1999-9999", AssetCriticality.MEDIUM)


async def test_lookup_invalid_cve() -> None:
    with pytest.raises(InputValidationError):
        await _service().lookup_cve("not-a-cve", AssetCriticality.MEDIUM)


async def test_lookup_multiple_deduplicates_and_reports_not_found() -> None:
    result = await _service().lookup_cves(
        ["CVE-2021-44228", "CVE-2021-44228", "CVE-1999-9999"],
        AssetCriticality.MEDIUM,
    )
    assert len(result.assessments) == 1
    assert result.not_found == ["CVE-1999-9999"]
    assert result.failed == []
    nvd = result.sources[0]
    assert nvd.source == "nvd"
    assert nvd.status.value == "ok"


async def test_lookup_rejects_empty_and_too_many() -> None:
    service = _service()
    with pytest.raises(InputValidationError):
        await service.lookup_cves([], AssetCriticality.LOW)
    with pytest.raises(InputValidationError):
        await service.lookup_cves([f"CVE-2024-{index:04d}" for index in range(21)], AssetCriticality.LOW)


async def test_search_returns_ranked_results() -> None:
    response = await _service().search_cves(
        keyword="log4j",
        limit=5,
        asset_criticality=AssetCriticality.HIGH,
    )
    assert response.query == "log4j"
    assert response.total_matches >= 1
    assert response.returned == len(response.results)
    assert response.results[0].cve.cve_id == "CVE-2021-44228"
    scores = [item.risk.score for item in response.results]
    assert scores == sorted(scores, reverse=True)


async def test_search_cvss_floor_and_kev_only() -> None:
    service = _service()
    high = await service.search_cves(
        keyword="apache",
        limit=10,
        asset_criticality=AssetCriticality.MEDIUM,
        cvss_min=9.0,
        kev_only=True,
    )
    assert high.results
    assert all(item.cve.kev is not None for item in high.results)
    assert all(item.cve.cvss is not None and item.cve.cvss.base_score >= 9.0 for item in high.results)


async def test_search_no_matches() -> None:
    response = await _service().search_cves(
        keyword="zzzz-no-such-package",
        limit=5,
        asset_criticality=AssetCriticality.MEDIUM,
    )
    assert response.total_matches == 0
    assert response.results == []


async def test_scan_packages_vulnerable_and_safe() -> None:
    service = _service()
    vulnerable = await service.scan_packages(
        [
            PackageQuery(
                name="org.apache.logging.log4j:log4j-core",
                ecosystem=Ecosystem.MAVEN,
                version="2.14.1",
            )
        ]
    )
    assert vulnerable.total_vulnerabilities == 1
    advisory = vulnerable.vulnerabilities[0]
    assert advisory.advisory_id == "GHSA-jfh8-c2jp-5v3q"
    assert advisory.fixed_versions == ["2.15.0"]
    assert advisory.references

    safe = await service.scan_packages([PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="4.17.21")])
    assert safe.total_vulnerabilities == 0


async def test_scan_packages_validates_input() -> None:
    service = _service()
    with pytest.raises(InputValidationError):
        await service.scan_packages([])
    with pytest.raises(InputValidationError):
        await service.scan_packages([PackageQuery(name="lodash", ecosystem=Ecosystem.NPM) for _ in range(21)])


async def test_prompt_injection_fixture_is_sanitized() -> None:
    assessment = await _service().lookup_cve("CVE-2099-0001", AssetCriticality.MEDIUM)
    description = assessment.cve.description
    assert "\x1b" not in description
    assert "\u202e" not in description
    assert "\x00" not in description
    assert assessment.cve.trust == "untrusted_external"


async def test_public_kev_and_epss_helpers() -> None:
    service = _service()
    kev = await service.kev_catalog()
    assert kev.report.status.value == "ok"
    assert "CVE-2021-44228" in kev.value
    epss = await service.epss_scores(["CVE-2021-44228", "CVE-1999-9999"])
    assert set(epss.value) == {"CVE-2021-44228"}


async def test_nvd_api_key_header_is_sent() -> None:
    fake = FakeHttp(fixture_nvd_payload())
    settings = offline_settings(
        offline=False,
        nvd_api_key="k" * 40,
    )
    service = IntelService(
        settings=settings,
        http=fake,  # type: ignore[arg-type]
        cache=TTLCache(),
        telemetry=configure_observability(settings),
    )
    assessment = await service.lookup_cve("CVE-2021-44228", AssetCriticality.MEDIUM)
    assert assessment.cve.cve_id == "CVE-2021-44228"
    nvd_calls = [call for call in fake.calls if call["url"].startswith("https://services.nvd.nist.gov")]
    assert nvd_calls
    assert nvd_calls[0]["headers"] == {"apiKey": "k" * 40}


async def test_total_upstream_failure_is_raised() -> None:
    fake = FakeHttp(None, error=UpstreamError("nvd", "down"))
    settings = offline_settings(offline=False)
    service = IntelService(
        settings=settings,
        http=fake,  # type: ignore[arg-type]
        cache=TTLCache(),
        telemetry=configure_observability(settings),
    )
    with pytest.raises(UpstreamError):
        await service.lookup_cve("CVE-2021-44228", AssetCriticality.MEDIUM)
    with pytest.raises(UpstreamError):
        await service.search_cves(keyword="log4j", limit=5, asset_criticality=AssetCriticality.MEDIUM)
    with pytest.raises(UpstreamError):
        await service.scan_packages([PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="4.17.15")])


async def test_osv_failure_is_raised_when_all_packages_fail() -> None:
    fake = FakeHttp(None, error=UpstreamError("osv", "down"))
    settings = offline_settings(offline=False)
    service = IntelService(
        settings=settings,
        http=fake,  # type: ignore[arg-type]
        cache=TTLCache(),
        telemetry=configure_observability(settings),
    )
    with pytest.raises(UpstreamError, match="osv"):
        await service.scan_packages([PackageQuery(name="lodash", ecosystem=Ecosystem.NPM)])


def test_nvd_parser_edge_cases() -> None:
    parsed = IntelService._parse_nvd_cve(
        {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "de", "value": "ignored"}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"version": "3.1", "baseScore": "bad"}},
                ],
                "cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
            },
            "references": [
                {"url": "javascript:alert(1)"},
                {"url": "https://example.test/advisory"},
                {"url": "https://example.test/advisory"},
            ],
        }
    )
    assert parsed.cve_id == "CVE-2024-0001"
    assert parsed.title == "CVE-2024-0001"
    assert parsed.description == ""
    assert parsed.cvss is not None
    assert parsed.cvss.base_score == 9.0
    assert parsed.references == ["https://example.test/advisory"]


def test_nvd_parser_bad_identifier() -> None:
    with pytest.raises(InputValidationError):
        IntelService._parse_nvd_cve({"id": "bogus"})


def test_nvd_search_parser_errors() -> None:
    with pytest.raises(UpstreamError):
        IntelService._parse_nvd_search("nope")
    with pytest.raises(UpstreamError):
        IntelService._parse_nvd_search({})
    records, total = IntelService._parse_nvd_search(
        {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "bad"}}, {"cve": {"id": "CVE-2024-0002"}}]}
    )
    assert total == 3
    assert [record.cve_id for record in records] == ["CVE-2024-0002"]


def test_find_nvd_record() -> None:
    assert IntelService._find_nvd_record("nope", "CVE-2021-44228") is None
    assert IntelService._find_nvd_record({}, "CVE-2021-44228") is None
    assert IntelService._find_nvd_record({"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}, "CVE-2021-44228")


def test_epss_parser_edge_cases() -> None:
    with pytest.raises(UpstreamError):
        IntelService._parse_epss(None)
    with pytest.raises(UpstreamError):
        IntelService._parse_epss({})
    parsed = IntelService._parse_epss(
        {
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.5", "percentile": "bad", "date": "2026-01-01"},
                {"cve": "NOT-A-CVE", "epss": "0.1"},
                {"cve": "CVE-2024-0002", "epss": "not-a-number"},
                "junk",
            ]
        }
    )
    assert set(parsed) == {"CVE-2021-44228"}
    assert parsed["CVE-2021-44228"].percentile is None


def test_kev_parser_edge_cases() -> None:
    with pytest.raises(UpstreamError):
        IntelService._parse_kev([])
    with pytest.raises(UpstreamError):
        IntelService._parse_kev({})
    parsed = IntelService._parse_kev(
        {
            "vulnerabilities": [
                {"cveID": "bad"},
                "junk",
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "RCE",
                    "knownRansomwareCampaignUse": "Known",
                },
            ]
        }
    )
    assert parsed["CVE-2021-44228"].known_ransomware_use is True


def test_osv_parser_edge_cases() -> None:
    with pytest.raises(UpstreamError):
        IntelService._parse_osv(None, PackageQuery(name="lodash", ecosystem=Ecosystem.NPM), "lodash", None)
    with pytest.raises(UpstreamError):
        IntelService._parse_osv({"vulns": "bad"}, PackageQuery(name="lodash", ecosystem=Ecosystem.NPM), "lodash", None)
    parsed = IntelService._parse_osv(
        {
            "vulns": [
                {"id": ""},
                "junk",
                {
                    "id": "GHSA-xxxx",
                    "summary": "x" * 2_000,
                    "severity": [{"score": "CVSS:3.1/..."}],
                    "affected": [{"ranges": [{"events": [{"fixed": "1.2.3"}, {"fixed": "1.2.3"}]}]}],
                    "references": [{"url": "https://example.test/a"}],
                    "aliases": ["CVE-2024-0001"],
                },
            ]
        },
        PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="1.0.0"),
        "lodash",
        "1.0.0",
    )
    assert len(parsed) == 1
    assert parsed[0].fixed_versions == ["1.2.3"]
    assert len(parsed[0].summary) <= 1_000
    assert parsed[0].severity == "CVSS:3.1/..."


def test_fixture_payloads_are_snapshot_shaped() -> None:
    assert fixture_nvd_payload()["totalResults"] == len(fixture_nvd_payload()["vulnerabilities"])
    assert fixture_osv_payload("lodash", "npm", "4.17.15")["vulns"]
    assert fixture_osv_payload("lodash", "npm", "4.17.21")["vulns"] == []
