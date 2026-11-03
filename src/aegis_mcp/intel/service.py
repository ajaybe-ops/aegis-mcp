"""Vulnerability intelligence orchestration over NVD, FIRST EPSS, CISA KEV, and OSV."""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import anyio

from ..config import Settings
from ..domain.errors import InputValidationError, NotFoundError, UpstreamError
from ..domain.models import (
    AssetCriticality,
    CveAssessment,
    CveIntel,
    CvssData,
    EpssScore,
    KevEntry,
    PackageQuery,
    PackageScanResponse,
    PackageVulnerability,
    SearchResponse,
    SourceReport,
    SourceStatus,
)
from ..domain.risk import assess_risk
from ..domain.sanitize import (
    clean_untrusted,
    normalize_cve_id,
    safe_url,
    validate_package_name,
    validate_version,
)
from ..infra.cache import TTLCache
from ..infra.telemetry import Observability
from .fixtures import (
    fixture_kev_payload,
    fixture_nvd_payload,
    fixture_osv_payload,
)
from .http import ResilientHttpClient

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

FIXTURE_DETAIL = "offline fixture snapshot; not live data"


@dataclass
class Fetched:
    value: Any = None
    report: SourceReport = field(
        default_factory=lambda: SourceReport(source="unknown", status=SourceStatus.UNAVAILABLE)
    )
    cache_hit: bool = False


@dataclass
class _Envelope:
    found: bool
    value: Any = None
    failed: bool = False


@dataclass
class MultiCveResult:
    assessments: list[CveAssessment]
    not_found: list[str]
    failed: list[dict[str, str]]
    sources: list[SourceReport]
    cache_hits: int


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def _source_report(
    name: str,
    *,
    status: SourceStatus,
    cached: bool,
    latency_ms: int,
    records: int,
    detail: str | None = None,
) -> SourceReport:
    return SourceReport(
        source=name,
        status=status,
        cached=cached,
        latency_ms=latency_ms,
        records=records,
        fetched_at=_now(),
        detail=clean_untrusted(detail, max_length=512) if detail else None,
    )


def _error_detail(exc: Exception) -> str:
    public_message = getattr(exc, "public_message", None)
    if callable(public_message):
        return str(public_message())
    return type(exc).__name__


class IntelService:
    def __init__(
        self,
        *,
        settings: Settings,
        http: ResilientHttpClient | None,
        cache: TTLCache,
        telemetry: Observability,
    ) -> None:
        self._settings = settings
        self._http = http
        self._cache = cache
        self._telemetry = telemetry
        self._offline = settings.offline

    def _nvd_headers(self) -> dict[str, str] | None:
        if self._settings.nvd_api_key is None:
            return None
        return {"apiKey": self._settings.nvd_api_key.get_secret_value()}

    async def kev_catalog(self) -> Fetched:
        return await self._load_kev()

    async def epss_scores(self, cve_ids: list[str]) -> Fetched:
        return await self._load_epss(cve_ids)

    # ------------------------------------------------------------------ cache
    async def _cached(self, key: str, ttl: int, loader: Callable[[], Awaitable[Any]]) -> tuple[Any, bool]:
        value, hit = await self._cache.get_or_create(key, loader, ttl_seconds=ttl)
        self._telemetry.cache_requests.add(1, {"cache": "intel", "result": "hit" if hit else "miss"})
        return value, hit

    @staticmethod
    def _cache_key(prefix: str, **parts: Any) -> str:
        raw = "|".join(f"{key}={parts[key]!r}" for key in sorted(parts))
        return f"{prefix}:{hashlib.sha256(raw.encode()).hexdigest()[:32]}"

    # -------------------------------------------------------------- providers
    async def _load_kev(self) -> Fetched:
        started = time.perf_counter()

        async def loader() -> dict[str, KevEntry]:
            if self._offline:
                payload: Any = fixture_kev_payload()
            else:
                if self._http is None:  # pragma: no cover - guarded by runtime construction
                    raise UpstreamError("kev", "HTTP client unavailable")
                payload = await self._http.request_json("GET", KEV_URL, provider="kev")
            return self._parse_kev(payload)

        try:
            value, hit = await self._cached("kev:index", self._settings.kev_cache_ttl_seconds, loader)
            return Fetched(
                value=value,
                report=_source_report(
                    "kev",
                    status=SourceStatus.OK,
                    cached=hit,
                    latency_ms=0 if hit else int((time.perf_counter() - started) * 1000),
                    records=len(value),
                    detail=FIXTURE_DETAIL if self._offline else None,
                ),
                cache_hit=hit,
            )
        except Exception as exc:
            return Fetched(
                value={},
                report=_source_report(
                    "kev",
                    status=SourceStatus.UNAVAILABLE,
                    cached=False,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    records=0,
                    detail=_error_detail(exc),
                ),
            )

    async def _load_nvd_cve(self, cve_id: str) -> Fetched:
        started = time.perf_counter()

        async def loader() -> _Envelope:
            if self._offline:
                payload: Any = fixture_nvd_payload()
            else:
                if self._http is None:  # pragma: no cover
                    raise UpstreamError("nvd", "HTTP client unavailable")
                payload = await self._http.request_json(
                    "GET",
                    NVD_CVE_URL,
                    provider="nvd",
                    params={"cveId": cve_id},
                    headers=self._nvd_headers(),
                    allow_404=True,
                )
            found = self._find_nvd_record(payload, cve_id)
            return _Envelope(found=found is not None, value=found)

        try:
            envelope, hit = await self._cached(
                self._cache_key("nvd:cve", cve_id=cve_id), self._settings.cache_ttl_seconds, loader
            )
            return Fetched(
                value=envelope,
                report=_source_report(
                    "nvd",
                    status=SourceStatus.OK,
                    cached=hit,
                    latency_ms=0 if hit else int((time.perf_counter() - started) * 1000),
                    records=1 if envelope.found else 0,
                    detail=(FIXTURE_DETAIL if self._offline else ("not found" if not envelope.found else None)),
                ),
                cache_hit=hit,
            )
        except Exception as exc:
            return Fetched(
                value=_Envelope(found=False, failed=True),
                report=_source_report(
                    "nvd",
                    status=SourceStatus.UNAVAILABLE,
                    cached=False,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    records=0,
                    detail=_error_detail(exc),
                ),
            )

    async def _load_epss(self, cve_ids: list[str]) -> Fetched:
        if not cve_ids:
            return Fetched(value={}, report=SourceReport(source="epss", status=SourceStatus.SKIPPED))
        started = time.perf_counter()

        async def loader() -> dict[str, EpssScore]:
            if self._offline:
                payload: Any = {
                    "status": "OK",
                    "data": [{"cve": cve_id, **record} for cve_id, record in _fixture_epss_records(cve_ids).items()],
                }
            else:
                if self._http is None:  # pragma: no cover
                    raise UpstreamError("epss", "HTTP client unavailable")
                payload = await self._http.request_json(
                    "GET", EPSS_URL, provider="epss", params={"cve": ",".join(sorted(set(cve_ids)))}
                )
            return self._parse_epss(payload)

        try:
            value, hit = await self._cached(
                self._cache_key("epss", cves=sorted(set(cve_ids))), self._settings.cache_ttl_seconds, loader
            )
            return Fetched(
                value=value,
                report=_source_report(
                    "epss",
                    status=SourceStatus.OK,
                    cached=hit,
                    latency_ms=0 if hit else int((time.perf_counter() - started) * 1000),
                    records=len(value),
                    detail=FIXTURE_DETAIL if self._offline else None,
                ),
                cache_hit=hit,
            )
        except Exception as exc:
            return Fetched(
                value={},
                report=_source_report(
                    "epss",
                    status=SourceStatus.UNAVAILABLE,
                    cached=False,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    records=0,
                    detail=_error_detail(exc),
                ),
            )

    async def _load_nvd_search(self, keyword: str, limit: int) -> Fetched:
        started = time.perf_counter()

        async def loader() -> _Envelope:
            if self._offline:
                payload: Any = fixture_nvd_payload()
            else:
                if self._http is None:  # pragma: no cover
                    raise UpstreamError("nvd", "HTTP client unavailable")
                payload = await self._http.request_json(
                    "GET",
                    NVD_CVE_URL,
                    provider="nvd",
                    params={"keywordSearch": keyword, "resultsPerPage": min(limit, 50)},
                    headers=self._nvd_headers(),
                )
            records, total = self._parse_nvd_search(payload)
            needle = keyword.casefold()
            if self._offline:
                records = [
                    record
                    for record in records
                    if needle in record.cve_id.casefold()
                    or needle in record.title.casefold()
                    or needle in record.description.casefold()
                ]
                total = len(records)
            return _Envelope(found=True, value=(records[:limit], total))

        try:
            envelope, hit = await self._cached(
                self._cache_key("nvd:search", keyword=keyword.casefold(), limit=limit),
                self._settings.cache_ttl_seconds,
                loader,
            )
            records, total = envelope.value if envelope.value else ([], 0)
            return Fetched(
                value=(records, total),
                report=_source_report(
                    "nvd",
                    status=SourceStatus.OK,
                    cached=hit,
                    latency_ms=0 if hit else int((time.perf_counter() - started) * 1000),
                    records=len(records),
                    detail=FIXTURE_DETAIL if self._offline else None,
                ),
                cache_hit=hit,
            )
        except Exception as exc:
            return Fetched(
                value=([], 0),
                report=_source_report(
                    "nvd",
                    status=SourceStatus.UNAVAILABLE,
                    cached=False,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    records=0,
                    detail=_error_detail(exc),
                ),
            )

    async def _load_osv(self, query: PackageQuery) -> Fetched:
        started = time.perf_counter()
        name = validate_package_name(query.name)
        version = validate_version(query.version)
        key = self._cache_key("osv", name=name, ecosystem=query.ecosystem.value, version=version or "")

        async def loader() -> list[PackageVulnerability]:
            if self._offline:
                payload: Any = fixture_osv_payload(name, query.ecosystem.value, version)
            else:
                if self._http is None:  # pragma: no cover
                    raise UpstreamError("osv", "HTTP client unavailable")
                body: dict[str, Any] = {"package": {"name": name, "ecosystem": query.ecosystem.value}}
                if version:
                    body["version"] = version
                payload = await self._http.request_json("POST", OSV_QUERY_URL, provider="osv", json_body=body)
            return self._parse_osv(payload, query, name, version)

        try:
            value, hit = await self._cached(key, self._settings.cache_ttl_seconds, loader)
            return Fetched(
                value=value,
                report=_source_report(
                    "osv",
                    status=SourceStatus.OK,
                    cached=hit,
                    latency_ms=0 if hit else int((time.perf_counter() - started) * 1000),
                    records=len(value),
                    detail=FIXTURE_DETAIL if self._offline else None,
                ),
                cache_hit=hit,
            )
        except Exception as exc:
            return Fetched(
                value=[],
                report=_source_report(
                    "osv",
                    status=SourceStatus.UNAVAILABLE,
                    cached=False,
                    latency_ms=int((time.perf_counter() - started) * 1000),
                    records=0,
                    detail=_error_detail(exc),
                ),
            )

    # ------------------------------------------------------------------- tools
    async def lookup_cves(self, cve_ids: list[str], asset_criticality: AssetCriticality) -> MultiCveResult:
        started = time.perf_counter()
        normalized = list(dict.fromkeys(normalize_cve_id(item) for item in cve_ids))
        if not normalized:
            raise InputValidationError("at least one CVE identifier is required")
        if len(normalized) > 20:
            raise InputValidationError("at most 20 CVE identifiers may be assessed per call")

        nvd_results: dict[str, Fetched] = {}
        results: dict[str, Fetched] = {}

        async def run_nvd(cve_id: str) -> None:
            nvd_results[cve_id] = await self._load_nvd_cve(cve_id)

        async def run_shared(name: str, awaitable: Awaitable[Fetched]) -> None:
            results[name] = await awaitable

        async with anyio.create_task_group() as tg:
            for cve_id in normalized:
                tg.start_soon(run_nvd, cve_id)
            tg.start_soon(run_shared, "epss", self._load_epss(normalized))
            tg.start_soon(run_shared, "kev", self._load_kev())

        epss = results["epss"]
        kev = results["kev"]
        scores = dict(epss.value or {})
        kev_index = dict(kev.value or {})
        assessments: list[CveAssessment] = []
        not_found: list[str] = []
        failed: list[dict[str, str]] = []
        nvd_ok = 0
        cache_hits = sum(1 for item in (epss, kev) if item.cache_hit)

        for cve_id in normalized:
            fetched = nvd_results[cve_id]
            envelope: _Envelope = fetched.value
            cache_hits += int(fetched.cache_hit)
            intel: CveIntel | None = None
            if envelope.found and envelope.value is not None:
                intel = envelope.value
                nvd_ok += 1
            elif cve_id in kev_index:
                entry = kev_index[cve_id]
                intel = CveIntel(
                    cve_id=cve_id,
                    title=entry.name,
                    description=entry.description,
                    trust="untrusted_external",
                )
            else:
                if envelope.failed:
                    failed.append({"cve_id": cve_id, "detail": fetched.report.detail or "lookup failed"})
                else:
                    not_found.append(cve_id)
                continue
            if cve_id in kev_index:
                intel = intel.model_copy(update={"kev": kev_index[cve_id]})
            if cve_id in scores:
                intel = intel.model_copy(update={"epss": scores[cve_id]})
            assessments.append(
                CveAssessment(
                    cve=intel,
                    risk=assess_risk(
                        cvss=intel.cvss,
                        epss=intel.epss,
                        kev=intel.kev,
                        asset_criticality=asset_criticality,
                    ),
                    sources=[fetched.report, epss.report, kev.report],
                    cache_hits=sum(1 for item in (fetched, epss, kev) if item.cache_hit),
                    took_ms=int((time.perf_counter() - started) * 1000),
                )
            )

        assessments.sort(key=lambda item: item.risk.score, reverse=True)
        # A CVE that is simply absent from NVD is not a provider failure. Degrade
        # only when an actual lookup failed, so agents can distinguish "no such
        # CVE" from "NVD is unavailable".
        nvd_status = SourceStatus.DEGRADED if failed else SourceStatus.OK
        nvd_report = _source_report(
            "nvd",
            status=nvd_status,
            cached=all(item.cache_hit for item in nvd_results.values()) if nvd_results else False,
            latency_ms=max((item.report.latency_ms for item in nvd_results.values()), default=0),
            records=nvd_ok,
            detail=f"{len(failed)} lookup(s) failed" if failed else None,
        )
        return MultiCveResult(
            assessments=assessments,
            not_found=not_found,
            failed=failed,
            sources=[nvd_report, epss.report, kev.report],
            cache_hits=cache_hits,
        )

    async def lookup_cve(self, cve_id: str, asset_criticality: AssetCriticality) -> CveAssessment:
        normalized = normalize_cve_id(cve_id)
        result = await self.lookup_cves([normalized], asset_criticality)
        if result.assessments:
            return result.assessments[0]
        if result.failed:
            raise UpstreamError("intel", f"no upstream could resolve {normalized}", detail=result.failed[0]["detail"])
        raise NotFoundError(f"{normalized} was not found in NVD or the CISA KEV catalog")

    async def search_cves(
        self,
        *,
        keyword: str,
        limit: int,
        asset_criticality: AssetCriticality,
        cvss_min: float | None = None,
        kev_only: bool = False,
    ) -> SearchResponse:
        started = time.perf_counter()
        search = await self._load_nvd_search(keyword, limit)
        if search.report.status is SourceStatus.UNAVAILABLE:
            raise UpstreamError("nvd", "keyword search is unavailable", detail=search.report.detail)
        records, total = search.value
        ids = [record.cve_id for record in records]

        epss = await self._load_epss(ids)
        kev = await self._load_kev()
        scores = dict(epss.value or {})
        kev_index = dict(kev.value or {})
        if kev_only and kev.report.status is SourceStatus.UNAVAILABLE:
            raise UpstreamError("kev", "kev_only filtering requires the KEV catalog", detail=kev.report.detail)

        assessments: list[CveAssessment] = []
        for record in records:
            enriched = record
            if record.cve_id in scores:
                enriched = enriched.model_copy(update={"epss": scores[record.cve_id]})
            if record.cve_id in kev_index:
                enriched = enriched.model_copy(update={"kev": kev_index[record.cve_id]})
            if cvss_min is not None and (enriched.cvss is None or enriched.cvss.base_score < cvss_min):
                continue
            if kev_only and enriched.kev is None:
                continue
            assessments.append(
                CveAssessment(
                    cve=enriched,
                    risk=assess_risk(
                        cvss=enriched.cvss,
                        epss=enriched.epss,
                        kev=enriched.kev,
                        asset_criticality=asset_criticality,
                    ),
                    sources=[search.report, epss.report, kev.report],
                    cache_hits=sum(1 for item in (search, epss, kev) if item.cache_hit),
                    took_ms=int((time.perf_counter() - started) * 1000),
                )
            )
        assessments.sort(key=lambda item: item.risk.score, reverse=True)
        return SearchResponse(
            query=keyword,
            total_matches=int(total),
            returned=len(assessments),
            results=assessments[:limit],
            sources=[search.report, epss.report, kev.report],
            cache_hits=sum(1 for item in (search, epss, kev) if item.cache_hit),
            truncated=int(total) > len(assessments),
            took_ms=int((time.perf_counter() - started) * 1000),
        )

    async def scan_packages(self, queries: list[PackageQuery]) -> PackageScanResponse:
        started = time.perf_counter()
        if not queries:
            raise InputValidationError("at least one package is required")
        if len(queries) > 20:
            raise InputValidationError("at most 20 packages may be scanned per call")
        results: list[Fetched] = [Fetched() for _ in queries]

        async def run(index: int, query: PackageQuery) -> None:
            results[index] = await self._load_osv(query)

        async with anyio.create_task_group() as tg:
            for index, query in enumerate(queries):
                tg.start_soon(run, index, query)

        vulnerabilities: list[PackageVulnerability] = []
        seen: set[tuple[str, str, str | None]] = set()
        sources: list[SourceReport] = []
        cache_hits = 0
        failures = 0
        for fetched in results:
            sources.append(fetched.report)
            cache_hits += int(fetched.cache_hit)
            if fetched.report.status is SourceStatus.UNAVAILABLE:
                failures += 1
            for vuln in fetched.value or []:
                key = (vuln.advisory_id, vuln.package, vuln.version)
                if key not in seen:
                    seen.add(key)
                    vulnerabilities.append(vuln)
        if failures == len(results):
            detail = "; ".join(filter(None, (source.detail for source in sources)))
            raise UpstreamError("osv", "package advisory lookup is unavailable", detail=detail)
        vulnerabilities.sort(key=lambda item: item.advisory_id)
        return PackageScanResponse(
            packages=queries,
            total_vulnerabilities=len(vulnerabilities),
            vulnerabilities=vulnerabilities[:100],
            sources=sources,
            cache_hits=cache_hits,
            took_ms=int((time.perf_counter() - started) * 1000),
        )

    # ----------------------------------------------------------------- parsers
    @staticmethod
    def _find_nvd_record(payload: Any, cve_id: str) -> CveIntel | None:
        if not isinstance(payload, dict):
            return None
        items = payload.get("vulnerabilities")
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, dict):
                continue
            record = item.get("cve")
            if isinstance(record, dict) and str(record.get("id", "")).upper() == cve_id:
                return IntelService._parse_nvd_cve(record)
        return None

    @staticmethod
    def _parse_nvd_search(payload: Any) -> tuple[list[CveIntel], int]:
        if not isinstance(payload, dict):
            raise UpstreamError("nvd", "unexpected search payload", retryable=False)
        items = payload.get("vulnerabilities")
        if not isinstance(items, list):
            raise UpstreamError("nvd", "search payload missing vulnerabilities", retryable=False)
        records: list[CveIntel] = []
        for item in items[:50]:
            if isinstance(item, dict) and isinstance(item.get("cve"), dict):
                try:
                    records.append(IntelService._parse_nvd_cve(item["cve"]))
                except Exception as exc:
                    logger.debug("skipping unparsable NVD search record", exc_info=exc)
                    continue
        total = payload.get("totalResults", len(records))
        return records, int(total) if isinstance(total, int) else len(records)

    @staticmethod
    def _parse_nvd_cve(record: dict[str, Any]) -> CveIntel:
        cve_id = normalize_cve_id(str(record.get("id", "")))
        descriptions = record.get("descriptions")
        description = ""
        if isinstance(descriptions, list):
            for item in descriptions:
                if isinstance(item, dict) and item.get("lang") == "en" and isinstance(item.get("value"), str):
                    description = item["value"]
                    break
        description = clean_untrusted(description, max_length=8_000)
        title = description[:200].split(". ")[0].strip()
        if len(description) > len(title):
            title = title.rstrip(".") + "…"
        if not title:
            title = cve_id

        cvss: CvssData | None = None
        metrics = record.get("metrics")
        if isinstance(metrics, dict):
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key)
                if not isinstance(entries, list) or not entries:
                    continue
                entry = entries[0]
                data = entry.get("cvssData") if isinstance(entry, dict) else None
                if not isinstance(data, dict):
                    continue
                try:
                    raw_score = data.get("baseScore")
                    if raw_score is None:
                        continue
                    score = float(raw_score)
                except (TypeError, ValueError):
                    continue
                cvss = CvssData(
                    version=str(data.get("version", key.replace("cvssMetricV", "").replace("V", ".")))[:16],
                    base_score=max(0.0, min(10.0, score)),
                    vector=str(data.get("vectorString"))[:256] if data.get("vectorString") else None,
                    severity=str(data.get("baseSeverity") or entry.get("baseSeverity") or "")[:32] or None,
                    source="nvd",
                )
                break

        weaknesses: list[str] = []
        raw_weaknesses = record.get("weaknesses")
        if isinstance(raw_weaknesses, list):
            for weakness in raw_weaknesses:
                if not isinstance(weakness, dict):
                    continue
                for item in weakness.get("description", []):
                    if isinstance(item, dict) and isinstance(item.get("value"), str):
                        weaknesses.append(clean_untrusted(item["value"], max_length=32))

        references: list[str] = []
        raw_refs = record.get("references")
        if isinstance(raw_refs, list):
            for ref in raw_refs[:40]:
                if isinstance(ref, dict) and isinstance(ref.get("url"), str):
                    url = safe_url(ref["url"])
                    if url and url not in references:
                        references.append(url)

        return CveIntel(
            cve_id=cve_id,
            title=clean_untrusted(title, max_length=512),
            description=description,
            published=_parse_dt(record.get("published")),
            last_modified=_parse_dt(record.get("lastModified")),
            status=str(record.get("vulnStatus"))[:64] if record.get("vulnStatus") else None,
            cvss=cvss,
            weaknesses=list(dict.fromkeys(weaknesses))[:20],
            references=references[:20],
        )

    @staticmethod
    def _parse_epss(payload: Any) -> dict[str, EpssScore]:
        if not isinstance(payload, dict):
            raise UpstreamError("epss", "unexpected EPSS payload", retryable=False)
        data = payload.get("data")
        if not isinstance(data, list):
            raise UpstreamError("epss", "EPSS payload missing data", retryable=False)
        result: dict[str, EpssScore] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve", "")).upper()
            try:
                raw_score = item.get("epss")
                if raw_score is None:
                    continue
                score = float(raw_score)
            except (TypeError, ValueError):
                continue
            if not cve_id.startswith("CVE-"):
                continue
            try:
                percentile = float(item["percentile"]) if item.get("percentile") is not None else None
            except (TypeError, ValueError):
                percentile = None
            result[cve_id] = EpssScore(
                score=max(0.0, min(1.0, score)),
                percentile=max(0.0, min(1.0, percentile)) if percentile is not None else None,
                date=str(item.get("date"))[:32] if item.get("date") else None,
            )
        return result

    @staticmethod
    def _parse_kev(payload: Any) -> dict[str, KevEntry]:
        if not isinstance(payload, dict):
            raise UpstreamError("kev", "unexpected KEV payload", retryable=False)
        items = payload.get("vulnerabilities")
        if not isinstance(items, list):
            raise UpstreamError("kev", "KEV payload missing vulnerabilities", retryable=False)
        result: dict[str, KevEntry] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                cve_id = normalize_cve_id(str(item.get("cveID", "")))
            except InputValidationError:
                continue
            result[cve_id] = KevEntry(
                cve_id=cve_id,
                vendor=clean_untrusted(str(item.get("vendorProject", "")), max_length=256),
                product=clean_untrusted(str(item.get("product", "")), max_length=256),
                name=clean_untrusted(str(item.get("vulnerabilityName", "")), max_length=512),
                date_added=str(item.get("dateAdded"))[:32] if item.get("dateAdded") else None,
                due_date=str(item.get("dueDate"))[:32] if item.get("dueDate") else None,
                known_ransomware_use=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
                required_action=clean_untrusted(str(item.get("requiredAction", "")), max_length=2_000),
                description=clean_untrusted(str(item.get("shortDescription", "")), max_length=4_000),
            )
        return result

    @staticmethod
    def _parse_osv(payload: Any, query: PackageQuery, name: str, version: str | None) -> list[PackageVulnerability]:
        if not isinstance(payload, dict):
            raise UpstreamError("osv", "unexpected OSV payload", retryable=False)
        vulns = payload.get("vulns", [])
        if not isinstance(vulns, list):
            raise UpstreamError("osv", "OSV payload missing vulns", retryable=False)
        results: list[PackageVulnerability] = []
        for item in vulns[:50]:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            fixed_versions: list[str] = []
            severity: str | None = None
            raw_severity = item.get("severity")
            if isinstance(raw_severity, list) and raw_severity:
                first = raw_severity[0]
                if isinstance(first, dict) and first.get("score"):
                    severity = str(first["score"])[:64]
            affected = item.get("affected")
            if isinstance(affected, list):
                for entry in affected:
                    if not isinstance(entry, dict):
                        continue
                    for range_entry in entry.get("ranges", []):
                        if not isinstance(range_entry, dict):
                            continue
                        for event in range_entry.get("events", []):
                            if isinstance(event, dict) and event.get("fixed"):
                                fixed = str(event["fixed"])[:64]
                                if fixed not in fixed_versions:
                                    fixed_versions.append(fixed)
            references: list[str] = []
            for ref in item.get("references", [])[:40] if isinstance(item.get("references"), list) else []:
                if isinstance(ref, dict) and isinstance(ref.get("url"), str):
                    url = safe_url(ref["url"])
                    if url and url not in references:
                        references.append(url)
            aliases = [clean_untrusted(str(alias), max_length=64) for alias in item.get("aliases", [])[:20]]
            results.append(
                PackageVulnerability(
                    advisory_id=clean_untrusted(str(item["id"]), max_length=64),
                    aliases=aliases,
                    summary=clean_untrusted(str(item.get("summary", "")), max_length=1_000),
                    details=clean_untrusted(str(item.get("details", "")), max_length=8_000),
                    package=name,
                    ecosystem=query.ecosystem.value,
                    version=version,
                    published=_parse_dt(item.get("published")),
                    modified=_parse_dt(item.get("modified")),
                    fixed_versions=fixed_versions[:20],
                    severity=severity,
                    references=references[:20],
                )
            )
        return results


def _fixture_epss_records(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    from .fixtures import FIXTURE_EPSS

    return {cve_id: FIXTURE_EPSS[cve_id] for cve_id in cve_ids if cve_id in FIXTURE_EPSS}
