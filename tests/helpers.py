"""Shared test helpers: deterministic settings, MCP sessions, and report factories."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from mcp import ClientSession
from mcp.client._memory import InMemoryTransport

from aegis_mcp.config import Settings
from aegis_mcp.domain.models import (
    ActionItem,
    AssetCriticality,
    Coverage,
    CveIntel,
    CvssData,
    Finding,
    KevEntry,
    Priority,
    ReportStatus,
    RiskBand,
    TriageReport,
)
from aegis_mcp.domain.risk import POLICY_VERSION, assess_risk
from aegis_mcp.server import create_server


def offline_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "transport": "stdio",
        "auth_mode": "local",
        "offline": True,
        "otel_enabled": False,
        "log_level": "ERROR",
        "log_format": "console",
        "sqlite_path": ":memory:",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@asynccontextmanager
async def mcp_session(settings: Settings | None = None) -> AsyncIterator[ClientSession]:
    server = create_server(settings or offline_settings())
    async with InMemoryTransport(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def make_report(
    *,
    incident_id: str = "INC-TEST-1",
    report_id: str = "rpt_0123456789abcdef01234567",
    fingerprint: str = "a" * 64,
    status: ReportStatus = ReportStatus.COMPLETE,
) -> TriageReport:
    cvss = CvssData(version="3.1", base_score=9.8, severity="CRITICAL", source="nvd")
    kev = KevEntry(
        cve_id="CVE-2021-44228",
        vendor="Apache",
        product="Log4j2",
        name="Apache Log4j2 RCE",
        known_ransomware_use=True,
    )
    risk = assess_risk(
        cvss=cvss,
        epss=None,
        kev=kev,
        asset_criticality=AssetCriticality.HIGH,
    )
    finding = Finding(
        finding_id="cve:CVE-2021-44228",
        kind="cve",
        identifier="CVE-2021-44228",
        title="Apache Log4j2 RCE",
        summary="JNDI injection",
        risk=risk,
        cvss=cvss,
        kev=kev,
        affected_assets=["payments-api-1"],
    )
    return TriageReport(
        report_id=report_id,
        incident_id=incident_id,
        generated_at=datetime.now(UTC),
        status=status,
        summary=f"{incident_id}: 1 finding",
        asset_criticality=AssetCriticality.HIGH,
        risk_band=RiskBand.CRITICAL,
        max_risk_score=risk.score,
        findings=[finding],
        actions=[
            ActionItem(
                priority=Priority.P0,
                action="Patch known-exploited systems",
                rationale="Listed in CISA KEV",
            )
        ],
        sources=[],
        coverage=Coverage(
            requested_cves=1,
            assessed_cves=1,
            requested_packages=0,
            assessed_packages=0,
            failed_lookups=0,
        ),
        policy_version=POLICY_VERSION,
        input_fingerprint=fingerprint,
    )


def cve_intel(cve_id: str = "CVE-2021-44228") -> CveIntel:
    return CveIntel(
        cve_id=cve_id,
        title="Example",
        description="Example description",
    )
