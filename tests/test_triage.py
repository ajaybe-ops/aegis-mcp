"""Multi-step triage semantics: completion, degradation, timeouts, idempotency."""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from aegis_mcp.domain.errors import InputValidationError, UpstreamError
from aegis_mcp.domain.models import (
    AssetCriticality,
    Ecosystem,
    PackageQuery,
    ReportStatus,
)
from aegis_mcp.infra.cache import TTLCache
from aegis_mcp.infra.store import TriageStore
from aegis_mcp.infra.telemetry import configure_observability
from aegis_mcp.intel.service import IntelService
from aegis_mcp.workflows.triage import TriageInput, TriageService

from .helpers import offline_settings


async def _make_service() -> tuple[TriageService, TriageStore, IntelService]:
    settings = offline_settings()
    telemetry = configure_observability(settings)
    store = TriageStore(":memory:")
    await store.initialize()
    intel = IntelService(
        settings=settings,
        http=None,
        cache=TTLCache(),
        telemetry=telemetry,
    )
    return TriageService(intel=intel, store=store, telemetry=telemetry), store, intel


def _request(**overrides: Any) -> TriageInput:
    values: dict[str, Any] = {
        "incident_id": "INC-2026-001",
        "title": "Log4j exploitation attempt",
        "cve_ids": ["CVE-2021-44228"],
        "packages": [
            PackageQuery(
                name="org.apache.logging.log4j:log4j-core",
                ecosystem=Ecosystem.MAVEN,
                version="2.14.1",
            )
        ],
        "assets": ["payments-api-1"],
        "asset_criticality": AssetCriticality.CRITICAL,
        "deadline_seconds": 10,
    }
    values.update(overrides)
    return TriageInput(**values)


async def test_complete_triage_persists_report() -> None:
    service, store, _ = await _make_service()
    progress: list[float] = []
    notifications: list[str] = []

    async def on_progress(percent: float, message: str) -> None:
        progress.append(percent)

    async def on_notify(uri: str) -> None:
        notifications.append(uri)

    report = await service.run(_request(), progress=on_progress, notify=on_notify)
    assert report.status is ReportStatus.COMPLETE
    assert report.max_risk_score >= 90
    assert report.risk_band.value == "critical"
    assert len(report.findings) == 2
    assert report.findings[0].risk.score >= report.findings[-1].risk.score
    assert report.actions
    assert report.coverage.requested_cves == 1
    assert report.coverage.assessed_cves == 1
    assert report.coverage.assessed_packages == 1
    assert report.coverage.degraded is False
    assert report.partial_failures == []
    assert report.input_fingerprint
    assert progress[-1] == 100
    assert notifications == [f"aegis://incidents/{report.incident_id}"]
    stored = await store.get(report.incident_id)
    assert stored is not None
    assert stored.report_id == report.report_id
    await store.close()


async def test_identical_request_reuses_report() -> None:
    service, store, _ = await _make_service()
    first = await service.run(_request())
    second = await service.run(_request())
    assert second.reused_existing is True
    assert second.report_id == first.report_id
    assert second.input_fingerprint == first.input_fingerprint
    assert await store.count() == 1
    await store.close()


async def test_package_only_triage() -> None:
    service, store, _ = await _make_service()
    report = await service.run(
        _request(
            cve_ids=[],
            packages=[
                PackageQuery(
                    name="lodash",
                    ecosystem=Ecosystem.NPM,
                    version="4.17.15",
                )
            ],
        )
    )
    assert report.status is ReportStatus.COMPLETE
    assert len(report.findings) == 1
    assert report.findings[0].kind == "package"
    assert report.findings[0].fixed_versions == ["4.17.19"]
    await store.close()


async def test_unknown_cve_is_partial_not_failed() -> None:
    service, store, _ = await _make_service()
    report = await service.run(_request(cve_ids=["CVE-1999-9999"], packages=[], assets=[]))
    assert report.status is ReportStatus.PARTIAL
    assert report.findings == []
    assert report.coverage.degraded is True
    assert any("not found" in item for item in report.partial_failures)
    await store.close()


async def test_total_lookup_failure_is_failed() -> None:
    class FailingIntel:
        async def lookup_cves(self, *args: Any, **kwargs: Any) -> Any:
            raise UpstreamError("nvd", "down")

    settings = offline_settings()
    telemetry = configure_observability(settings)
    store = TriageStore(":memory:")
    await store.initialize()
    service = TriageService(intel=FailingIntel(), store=store, telemetry=telemetry)  # type: ignore[arg-type]
    report = await service.run(_request(packages=[]))
    assert report.status is ReportStatus.FAILED
    assert report.coverage.failed_lookups == 1
    await store.close()


async def test_all_package_failures_are_failed() -> None:
    class FailingIntel:
        async def scan_packages(self, *args: Any, **kwargs: Any) -> Any:
            raise UpstreamError("osv", "down")

    settings = offline_settings()
    telemetry = configure_observability(settings)
    store = TriageStore(":memory:")
    await store.initialize()
    service = TriageService(intel=FailingIntel(), store=store, telemetry=telemetry)  # type: ignore[arg-type]
    report = await service.run(
        _request(
            cve_ids=[],
            packages=[PackageQuery(name="lodash", ecosystem=Ecosystem.NPM)],
        )
    )
    assert report.status is ReportStatus.FAILED
    assert report.coverage.failed_lookups == 1
    await store.close()


@pytest.mark.slow
async def test_deadline_produces_partial_report() -> None:
    class SlowIntel:
        async def lookup_cves(self, *args: Any, **kwargs: Any) -> Any:
            await anyio.sleep(5)
            raise AssertionError("should be cancelled")

    settings = offline_settings()
    telemetry = configure_observability(settings)
    store = TriageStore(":memory:")
    await store.initialize()
    service = TriageService(intel=SlowIntel(), store=store, telemetry=telemetry)  # type: ignore[arg-type]
    report = await service.run(_request(cve_ids=["CVE-2021-44228"], packages=[], deadline_seconds=1))
    assert report.status is ReportStatus.PARTIAL
    assert report.coverage.timed_out is True
    assert any("deadline" in item for item in report.partial_failures)
    await store.close()


async def test_no_inputs_is_rejected() -> None:
    service, store, _ = await _make_service()
    with pytest.raises(InputValidationError):
        await service.run(_request(cve_ids=[], packages=[]))
    await store.close()


async def test_invalid_incident_id_is_rejected() -> None:
    service, store, _ = await _make_service()
    with pytest.raises(InputValidationError):
        await service.run(_request(incident_id="../bad"))
    await store.close()


def test_normalization_bounds_and_cleanup() -> None:
    request = TriageInput(
        incident_id=" INC-1 ",
        title="  bad\x1b[31m title  ",
        cve_ids=["cve-2021-44228", "CVE-2021-44228"],
        assets=[" payments-api-1 "],
        deadline_seconds=999,
    ).normalize()
    assert request.incident_id == "INC-1"
    assert request.title == "bad title"
    assert request.cve_ids == ["CVE-2021-44228"]
    assert request.assets == ["payments-api-1"]
    assert request.deadline_seconds == 25


def test_fingerprint_is_order_independent() -> None:
    first = TriageInput(
        incident_id="INC-1",
        title="x",
        cve_ids=["CVE-2021-44228", "CVE-2023-4863"],
        packages=[
            PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="4.17.15"),
            PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="4.17.16"),
        ],
        assets=["b", "a"],
    ).normalize()
    second = TriageInput(
        incident_id="INC-1",
        title="x",
        cve_ids=["CVE-2023-4863", "CVE-2021-44228"],
        packages=[
            PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="4.17.16"),
            PackageQuery(name="lodash", ecosystem=Ecosystem.NPM, version="4.17.15"),
        ],
        assets=["a", "b"],
    ).normalize()
    assert first.fingerprint() == second.fingerprint()


def test_fingerprint_changes_with_policy_relevant_input() -> None:
    base = TriageInput(incident_id="INC-1", title="x", cve_ids=["CVE-2021-44228"]).normalize()
    changed = TriageInput(
        incident_id="INC-1",
        title="x",
        cve_ids=["CVE-2021-44228"],
        asset_criticality=AssetCriticality.CRITICAL,
    ).normalize()
    assert base.fingerprint() != changed.fingerprint()


async def test_actions_include_kev_and_fixed_version_guidance() -> None:
    service, store, _ = await _make_service()
    report = await service.run(_request())
    actions = " ".join(action.action for action in report.actions)
    assert "known-exploited" in actions
    assert "2.15.0" in actions
    priorities = {action.priority.value for action in report.actions}
    assert "P0" in priorities
    await store.close()
