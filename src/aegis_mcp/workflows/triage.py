"""Multi-step incident triage: fetch -> enrich -> score -> prioritize -> persist.

The workflow degrades explicitly. It records which sources failed, never
fabricates missing evidence, and keeps per-stage results that completed before a
deadline cancellation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import anyio

from ..domain.errors import AegisError, InputValidationError
from ..domain.models import (
    ActionItem,
    AssetCriticality,
    Coverage,
    Finding,
    PackageQuery,
    PackageScanResponse,
    PackageVulnerability,
    Priority,
    ReportStatus,
    RiskBand,
    SourceStatus,
    TriageReport,
)
from ..domain.risk import POLICY_VERSION, assess_risk, band_for
from ..domain.sanitize import clean_untrusted, normalize_cve_id, validate_asset, validate_incident_id, validate_version
from ..infra.store import TriageStore
from ..infra.telemetry import Observability
from ..intel.service import IntelService, MultiCveResult

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[float, str], Awaitable[None]]
NotifyCallback = Callable[[str], Awaitable[None]]


@dataclass
class TriageInput:
    incident_id: str
    title: str
    cve_ids: list[str] = field(default_factory=list)
    packages: list[PackageQuery] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM
    deadline_seconds: int = 12

    def normalize(self) -> TriageInput:
        incident_id = validate_incident_id(self.incident_id)
        cves = list(dict.fromkeys(normalize_cve_id(item) for item in self.cve_ids))
        if len(cves) > 20:
            raise InputValidationError("at most 20 CVEs are accepted per incident")
        if len(self.packages) > 20:
            raise InputValidationError("at most 20 packages are accepted per incident")
        if not cves and not self.packages:
            raise InputValidationError("provide at least one cve_id or package")
        assets = list(dict.fromkeys(validate_asset(item) for item in self.assets))
        if len(assets) > 50:
            raise InputValidationError("at most 50 assets are accepted per incident")
        packages = [
            PackageQuery(
                name=item.name,
                ecosystem=item.ecosystem,
                version=validate_version(item.version),
            )
            for item in self.packages
        ]
        return TriageInput(
            incident_id=incident_id,
            title=clean_untrusted(self.title, max_length=256) or incident_id,
            cve_ids=cves,
            packages=packages,
            assets=assets,
            asset_criticality=self.asset_criticality,
            deadline_seconds=max(1, min(25, self.deadline_seconds)),
        )

    def fingerprint(self) -> str:
        payload = {
            "incident_id": self.incident_id,
            "title": self.title,
            "cve_ids": sorted(self.cve_ids),
            "packages": sorted(
                [item.model_dump(mode="json") for item in self.packages],
                key=lambda item: json.dumps(item, sort_keys=True),
            ),
            "assets": sorted(self.assets),
            "asset_criticality": self.asset_criticality.value,
            "policy": POLICY_VERSION,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TriageService:
    def __init__(
        self,
        *,
        intel: IntelService,
        store: TriageStore,
        telemetry: Observability,
    ) -> None:
        self._intel = intel
        self._store = store
        self._telemetry = telemetry

    async def run(
        self,
        request: TriageInput,
        *,
        progress: ProgressCallback | None = None,
        notify: NotifyCallback | None = None,
    ) -> TriageReport:
        started = time.perf_counter()
        request = request.normalize()
        fingerprint = request.fingerprint()
        await self._progress(progress, 2, "validated incident input")

        existing = await self._store.find(request.incident_id, fingerprint)
        if existing is not None:
            await self._progress(progress, 100, "reused identical prior report")
            self._telemetry.triage_findings.record(len(existing.findings), {"status": "reused"})
            return existing.model_copy(update={"reused_existing": True})

        deadline = time.monotonic() + max(0.5, request.deadline_seconds - 0.25)
        cve_result: MultiCveResult | None = None
        package_result: PackageScanResponse | None = None
        package_failures = 0
        failures: list[str] = []

        async def fetch_cves() -> None:
            nonlocal cve_result
            try:
                cve_result = await self._intel.lookup_cves(request.cve_ids, request.asset_criticality)
            except AegisError as exc:
                failures.append(f"cve lookup: {exc.public_message()}")
            except Exception:  # pragma: no cover - defensive
                logger.exception("unexpected CVE lookup failure")
                failures.append("cve lookup: internal error")
            finally:
                await self._progress(progress, 55, "CVE intelligence collected")

        async def fetch_packages() -> None:
            nonlocal package_result, package_failures
            if not request.packages:
                return
            try:
                package_result = await self._intel.scan_packages(request.packages)
                package_failures = sum(
                    1 for source in package_result.sources if source.status is SourceStatus.UNAVAILABLE
                )
            except AegisError as exc:
                failures.append(f"package scan: {exc.public_message()}")
                package_failures = len(request.packages)
            except Exception:  # pragma: no cover
                logger.exception("unexpected package scan failure")
                failures.append("package scan: internal error")
                package_failures = len(request.packages)
            finally:
                await self._progress(progress, 50, "package advisories collected")

        timed_out = False
        with anyio.move_on_after(max(0.1, deadline - time.monotonic())) as scope:
            async with anyio.create_task_group() as tg:
                if request.cve_ids:
                    tg.start_soon(fetch_cves)
                if request.packages:
                    tg.start_soon(fetch_packages)
        timed_out = scope.cancelled_caught
        if timed_out:
            failures.append("workflow deadline reached before all sources completed")

        await self._progress(progress, 65, "correlating findings")

        kev_index: dict[str, object] = {}
        alias_epss: dict[str, object] = {}
        if package_result is not None and package_result.vulnerabilities:
            aliases = _package_aliases(package_result.vulnerabilities)
            if aliases:
                with anyio.move_on_after(max(0.1, min(3.0, deadline - time.monotonic()))):
                    async with anyio.create_task_group() as tg:

                        async def get_kev() -> None:
                            nonlocal kev_index
                            fetched = await self._intel.kev_catalog()
                            kev_index = dict(fetched.value or {})

                        async def get_epss() -> None:
                            nonlocal alias_epss
                            fetched = await self._intel.epss_scores(aliases)
                            alias_epss = dict(fetched.value or {})

                        tg.start_soon(get_kev)
                        tg.start_soon(get_epss)

        findings: list[Finding] = []
        if cve_result is not None:
            for assessment in cve_result.assessments:
                findings.append(
                    Finding(
                        finding_id=f"cve:{assessment.cve.cve_id}",
                        kind="cve",
                        identifier=assessment.cve.cve_id,
                        title=assessment.cve.title,
                        summary=clean_untrusted(assessment.cve.description or assessment.cve.title, max_length=2_000),
                        risk=assessment.risk,
                        cvss=assessment.cve.cvss,
                        epss=assessment.cve.epss,
                        kev=assessment.cve.kev,
                        fixed_versions=[],
                        affected_assets=request.assets,
                        references=assessment.cve.references,
                    )
                )
            failures.extend(
                f"{item['cve_id']}: {clean_untrusted(item['detail'], max_length=200)}" for item in cve_result.failed
            )
            failures.extend(f"{cve_id}: not found in NVD or KEV" for cve_id in cve_result.not_found)

        package_findings: list[Finding] = []
        if package_result is not None:
            for vuln in package_result.vulnerabilities:
                alias = next((item for item in vuln.aliases if item.startswith("CVE-")), None)
                kev_entry = kev_index.get(alias) if alias else None
                epss_entry = alias_epss.get(alias) if alias else None
                risk = assess_risk(
                    cvss=None,
                    epss=epss_entry if hasattr(epss_entry, "score") else None,  # type: ignore[arg-type]
                    kev=kev_entry if hasattr(kev_entry, "cve_id") else None,  # type: ignore[arg-type]
                    asset_criticality=request.asset_criticality,
                )
                package_findings.append(
                    Finding(
                        finding_id=f"pkg:{vuln.advisory_id}:{vuln.package}",
                        kind="package",
                        identifier=vuln.advisory_id,
                        title=clean_untrusted(
                            vuln.summary or f"{vuln.package} advisory {vuln.advisory_id}", max_length=512
                        ),
                        summary=clean_untrusted(vuln.details or vuln.summary, max_length=2_000)
                        or f"{vuln.package} advisory {vuln.advisory_id}",
                        risk=risk,
                        fixed_versions=vuln.fixed_versions,
                        affected_assets=request.assets,
                        references=vuln.references,
                    )
                )

        findings.extend(package_findings)
        findings.sort(key=lambda item: item.risk.score, reverse=True)
        findings = findings[:50]
        max_score = findings[0].risk.score if findings else 0.0
        risk_band = band_for(max_score) if findings else RiskBand.INFO
        lookup_failures = len(cve_result.failed) if cve_result is not None else len(request.cve_ids)
        status = self._status(
            findings=findings,
            timed_out=timed_out,
            lookup_failures=lookup_failures,
            requested_cves=len(request.cve_ids),
            package_failures=package_failures,
            requested_packages=len(request.packages),
        )
        actions = self._actions(findings, request.asset_criticality, status)
        coverage = Coverage(
            requested_cves=len(request.cve_ids),
            assessed_cves=len(cve_result.assessments) if cve_result else 0,
            requested_packages=len(request.packages),
            assessed_packages=(len(package_result.sources) - package_failures if package_result is not None else 0),
            failed_lookups=lookup_failures + package_failures,
            timed_out=timed_out,
            degraded=status is not ReportStatus.COMPLETE,
        )

        report = TriageReport(
            report_id=f"rpt_{uuid.uuid4().hex[:24]}",
            incident_id=request.incident_id,
            generated_at=datetime.now(UTC),
            status=status,
            summary=self._summary(request, findings, risk_band, max_score, status, package_result),
            asset_criticality=request.asset_criticality,
            risk_band=risk_band,
            max_risk_score=max_score,
            findings=findings,
            actions=actions,
            sources=(cve_result.sources if cve_result else []) + (package_result.sources if package_result else []),
            coverage=coverage,
            partial_failures=[clean_untrusted(item, max_length=240) for item in failures[:30]],
            policy_version=POLICY_VERSION,
            input_fingerprint=fingerprint,
        )
        await self._store.save(report)
        await self._progress(progress, 95, "report persisted")
        if notify is not None:
            try:
                await notify(f"aegis://incidents/{request.incident_id}")
            except Exception:  # pragma: no cover - notification is best effort
                logger.debug("resource notification failed", exc_info=True)

        self._telemetry.triage_findings.record(len(findings), {"status": status.value})
        self._telemetry.triage_duration.record((time.perf_counter() - started) * 1000, {"status": status.value})
        await self._progress(progress, 100, "triage complete")
        return report

    @staticmethod
    async def _progress(callback: ProgressCallback | None, percent: float, message: str) -> None:
        if callback is None:
            return
        try:
            await callback(percent, message)
        except Exception:  # pragma: no cover - clients may not request progress
            logger.debug("progress notification failed", exc_info=True)

    @staticmethod
    def _status(
        *,
        findings: list[Finding],
        timed_out: bool,
        lookup_failures: int,
        requested_cves: int,
        package_failures: int,
        requested_packages: int,
    ) -> ReportStatus:
        """Classify the run without conflating "not found" with "provider failed".

        A CVE missing from every source is an answer, not an outage. It yields
        ``partial`` coverage so a human can decide whether the identifier was
        wrong. ``failed`` is reserved for the case where every requested lookup
        actually errored.
        """
        if timed_out:
            return ReportStatus.PARTIAL
        if findings:
            if lookup_failures or package_failures:
                return ReportStatus.PARTIAL
            return ReportStatus.COMPLETE
        cves_failed = requested_cves > 0 and lookup_failures >= requested_cves
        packages_failed = requested_packages > 0 and package_failures >= requested_packages
        all_failed = (requested_cves == 0 or cves_failed) and (requested_packages == 0 or packages_failed)
        if all_failed and (requested_cves or requested_packages):
            return ReportStatus.FAILED
        return ReportStatus.PARTIAL

    @staticmethod
    def _actions(findings: list[Finding], criticality: AssetCriticality, status: ReportStatus) -> list[ActionItem]:
        actions: list[ActionItem] = []
        seen: set[str] = set()

        def add(item: ActionItem) -> None:
            key = f"{item.priority}:{item.action}"
            if key not in seen and len(actions) < 10:
                seen.add(key)
                actions.append(item)

        kev_findings = [item for item in findings if item.kev is not None]
        if kev_findings:
            add(
                ActionItem(
                    priority=Priority.P0,
                    action="Patch or isolate known-exploited systems immediately",
                    rationale=f"{len(kev_findings)} finding(s) are listed in CISA KEV",
                    owner="incident-commander",
                    due_hint="KEV due date or sooner",
                )
            )
        for finding in findings:
            if finding.risk.band is RiskBand.CRITICAL:
                add(
                    ActionItem(
                        priority=Priority.P1,
                        action=f"Mitigate {finding.identifier} on exposed assets",
                        rationale=(
                            f"Composite score {finding.risk.score:.1f} (critical), "
                            f"confidence {finding.risk.confidence.value}"
                        ),
                        owner="security-engineering",
                        due_hint="24 hours",
                    )
                )
            if finding.fixed_versions:
                fixed = max(finding.fixed_versions)
                add(
                    ActionItem(
                        priority=Priority.P2,
                        action=f"Upgrade {finding.title[:120]} to {fixed} or later",
                        rationale=f"Advisory {finding.identifier} publishes a fixed version",
                        owner="service-owner",
                        due_hint="next maintenance window",
                    )
                )
            elif finding.kev is None and finding.risk.band in {RiskBand.CRITICAL, RiskBand.HIGH}:
                add(
                    ActionItem(
                        priority=Priority.P2,
                        action=f"Apply vendor mitigation for {finding.identifier}",
                        rationale="No fixed version was present in the retrieved advisory",
                        owner="service-owner",
                        due_hint="72 hours",
                    )
                )
        if criticality in {AssetCriticality.HIGH, AssetCriticality.CRITICAL}:
            add(
                ActionItem(
                    priority=Priority.P2,
                    action="Validate exposed services against the current SBOM",
                    rationale="Caller-declared asset criticality is high; version exposure is not auto-confirmed",
                    owner="platform-security",
                    due_hint="72 hours",
                )
            )
        if not findings:
            add(
                ActionItem(
                    priority=Priority.P3,
                    action="Increase deadline or retry when upstream sources recover",
                    rationale="No actionable findings were produced; inspect partial_failures before closing",
                    owner="security-engineering",
                    due_hint="retry window",
                )
            )
        if status is ReportStatus.PARTIAL:
            add(
                ActionItem(
                    priority=Priority.P3,
                    action="Re-run triage for complete coverage",
                    rationale="One or more sources were unavailable or the deadline expired",
                    owner="security-engineering",
                    due_hint="after source recovery",
                )
            )
        return actions

    @staticmethod
    def _summary(
        request: TriageInput,
        findings: list[Finding],
        risk_band: RiskBand,
        max_score: float,
        status: ReportStatus,
        package_result: PackageScanResponse | None,
    ) -> str:
        kev_count = sum(1 for item in findings if item.kev is not None)
        critical_count = sum(1 for item in findings if item.risk.band is RiskBand.CRITICAL)
        packages = package_result.total_vulnerabilities if package_result else 0
        return (
            f"{request.title[:160]}: {len(findings)} finding(s); highest {risk_band.value} "
            f"({max_score:.1f}/100); {critical_count} critical; {kev_count} known-exploited; "
            f"{packages} package advisory record(s). Status: {status.value}."
        )


def _package_aliases(vulnerabilities: list[PackageVulnerability]) -> list[str]:
    aliases = {
        alias for vuln in vulnerabilities for alias in vuln.aliases if alias.startswith("CVE-") and len(alias) < 32
    }
    return sorted(aliases)[:40]
