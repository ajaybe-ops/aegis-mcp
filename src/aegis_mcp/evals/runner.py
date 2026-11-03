"""Offline, deterministic evaluations against the real MCP server.

The suite is intentionally not a unit-test substitute. It drives the public MCP
surface through an in-memory transport, so it measures the contract an agent
actually sees: tool schemas, structured output, resources, prompts, sanitization,
partial-coverage semantics, and idempotency.

Every scenario runs with ``AEGIS_OFFLINE=1`` against curated fixtures. No result
here proves live-feed correctness; it proves the server behaves deterministically
when upstream responses are known.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp import ClientSession
from mcp.client._memory import InMemoryTransport
from mcp.types import TextContent, TextResourceContents

from ..config import Settings
from ..server import create_server

EvalFn = Callable[[ClientSession], Awaitable[None]]


@dataclass
class EvalResult:
    name: str
    passed: bool
    detail: str
    duration_ms: int


@dataclass
class Scenario:
    name: str
    description: str
    fn: EvalFn
    requires: list[str] = field(default_factory=list)


def _settings() -> Settings:
    return Settings(
        environment="test",
        transport="stdio",
        auth_mode="local",
        offline=True,
        otel_enabled=False,
        log_level="ERROR",
        log_format="console",
        sqlite_path=":memory:",
    )


@asynccontextmanager
async def _session() -> AsyncIterator[ClientSession]:
    server = create_server(_settings())
    async with InMemoryTransport(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


def _structured(result: Any) -> dict[str, Any]:
    if getattr(result, "is_error", False):
        text = " ".join(item.text for item in (result.content or []) if isinstance(item, TextContent))
        raise AssertionError(f"tool returned isError: {text[:300]}")
    structured = getattr(result, "structured_content", None)
    if not isinstance(structured, dict):
        raise AssertionError("tool did not return structured content")
    return structured


def _resource_text(contents: list[Any]) -> str:
    for item in contents:
        if isinstance(item, TextResourceContents):
            return item.text
    raise AssertionError("expected text resource contents")


# --------------------------------------------------------------------- scenarios
async def schema_contract(session: ClientSession) -> None:
    tools = (await session.list_tools()).tools
    names = {tool.name for tool in tools}
    expected = {
        "lookup_cve",
        "search_vulnerabilities",
        "scan_packages",
        "triage_incident",
        "get_incident_report",
        "server_health",
    }
    assert names == expected, f"tool surface drifted: {sorted(names)}"
    for tool in tools:
        assert tool.description and len(tool.description) > 40, f"{tool.name} has a weak description"
        assert tool.input_schema is not None, f"{tool.name} has no input schema"
    triage = next(tool for tool in tools if tool.name == "triage_incident")
    assert triage.annotations is not None
    assert triage.annotations.destructive_hint is False
    assert triage.annotations.idempotent_hint is True


async def lookup_known_cve(session: ClientSession) -> None:
    payload = _structured(
        await session.call_tool(
            "lookup_cve",
            {"cve_id": "CVE-2021-44228", "asset_criticality": "high"},
        )
    )
    assert payload["cve"]["cve_id"] == "CVE-2021-44228"
    assert payload["risk"]["score"] >= 90
    assert payload["risk"]["band"] == "critical"
    assert payload["cve"]["kev"] is not None
    assert payload["cve"]["epss"]["score"] > 0.9
    assert payload["cve"]["trust"] == "untrusted_external"
    factor_names = {factor["name"] for factor in payload["risk"]["factors"]}
    assert {"cvss_base", "epss", "known_exploited", "asset_criticality"} <= factor_names


async def lookup_missing_cve(session: ClientSession) -> None:
    result = await session.call_tool("lookup_cve", {"cve_id": "CVE-1999-9999"})
    assert result.is_error, "missing CVE should be an error result"
    text = " ".join(item.text for item in (result.content or []) if isinstance(item, TextContent))
    assert "AEGIS_NOT_FOUND" in text


async def search_ranks_by_risk(session: ClientSession) -> None:
    payload = _structured(await session.call_tool("search_vulnerabilities", {"keyword": "log4j", "limit": 5}))
    assert payload["returned"] >= 1
    results = payload["results"]
    assert results[0]["cve"]["cve_id"] == "CVE-2021-44228"
    scores = [item["risk"]["score"] for item in results]
    assert scores == sorted(scores, reverse=True)
    assert payload["sources"][0]["source"] == "nvd"


async def scan_vulnerable_package(session: ClientSession) -> None:
    payload = _structured(
        await session.call_tool(
            "scan_packages",
            {
                "packages": [
                    {
                        "name": "org.apache.logging.log4j:log4j-core",
                        "ecosystem": "Maven",
                        "version": "2.14.1",
                    }
                ]
            },
        )
    )
    assert payload["total_vulnerabilities"] == 1
    advisory = payload["vulnerabilities"][0]
    assert advisory["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert "CVE-2021-44228" in advisory["aliases"]
    assert "2.15.0" in advisory["fixed_versions"]


async def scan_safe_package(session: ClientSession) -> None:
    payload = _structured(
        await session.call_tool(
            "scan_packages",
            {"packages": [{"name": "lodash", "ecosystem": "npm", "version": "4.17.21"}]},
        )
    )
    assert payload["total_vulnerabilities"] == 0


async def prompt_injection_is_inert(session: ClientSession) -> None:
    payload = _structured(await session.call_tool("lookup_cve", {"cve_id": "CVE-2099-0001"}))
    description = payload["cve"]["description"]
    assert "\x1b" not in description
    assert "\u202e" not in description
    assert payload["cve"]["trust"] == "untrusted_external"
    assert payload["disclaimer"].startswith("Vulnerability metadata is untrusted")


async def triage_complete_and_persisted(session: ClientSession) -> None:
    payload = _structured(
        await session.call_tool(
            "triage_incident",
            {
                "incident_id": "EVAL-INC-1",
                "title": "Log4j exploitation attempt",
                "cve_ids": ["CVE-2021-44228"],
                "packages": [
                    {
                        "name": "org.apache.logging.log4j:log4j-core",
                        "ecosystem": "Maven",
                        "version": "2.14.1",
                    }
                ],
                "assets": ["payments-api-1"],
                "asset_criticality": "critical",
                "deadline_seconds": 10,
            },
        )
    )
    assert payload["status"] == "complete", payload["partial_failures"]
    assert payload["max_risk_score"] >= 90
    assert len(payload["findings"]) >= 2
    assert payload["findings"][0]["risk"]["score"] >= payload["findings"][-1]["risk"]["score"]
    assert payload["actions"], "triage produced no actions"
    assert payload["coverage"]["degraded"] is False

    stored = _structured(await session.call_tool("get_incident_report", {"incident_id": "EVAL-INC-1"}))
    assert stored["report_id"] == payload["report_id"]

    resource = await session.read_resource("aegis://incidents/EVAL-INC-1")
    document = json.loads(_resource_text(resource.contents))
    assert document["incident_id"] == "EVAL-INC-1"
    assert document["status"] == "complete"


async def triage_is_idempotent(session: ClientSession) -> None:
    request = {
        "incident_id": "EVAL-INC-2",
        "title": "Repeatable triage",
        "cve_ids": ["CVE-2023-4863"],
        "asset_criticality": "high",
        "deadline_seconds": 10,
    }
    first = _structured(await session.call_tool("triage_incident", request))
    second = _structured(await session.call_tool("triage_incident", request))
    assert first["report_id"] == second["report_id"]
    assert second["reused_existing"] is True
    assert first["input_fingerprint"] == second["input_fingerprint"]


async def unknown_cve_is_partial_not_failed(session: ClientSession) -> None:
    payload = _structured(
        await session.call_tool(
            "triage_incident",
            {
                "incident_id": "EVAL-INC-3",
                "title": "Unknown identifier",
                "cve_ids": ["CVE-1999-9999"],
                "deadline_seconds": 10,
            },
        )
    )
    assert payload["status"] == "partial"
    assert payload["coverage"]["degraded"] is True
    assert any("not found" in item for item in payload["partial_failures"])


async def resources_and_prompts(session: ClientSession) -> None:
    policy = json.loads(_resource_text((await session.read_resource("aegis://policy/risk")).contents))
    assert sum(policy["weights"].values()) == 100
    assert policy["known_exploited_floor"] == 60

    catalog = json.loads(_resource_text((await session.read_resource("aegis://catalog/sources")).contents))
    assert {source["name"] for source in catalog["sources"]} == {"nvd", "epss", "kev", "osv"}

    manifest = json.loads(_resource_text((await session.read_resource("aegis://server/manifest")).contents))
    assert manifest["authorization"]["bearer_required"] is False
    assert manifest["data_handling"]["secrets_in_resources"] is False

    prompt = await session.get_prompt(
        "triage_vulnerability",
        {"cve_id": "CVE-2021-44228", "asset_context": "public API"},
    )
    assert len(prompt.messages) == 1
    prompt_content = prompt.messages[0].content
    text = prompt_content.text if isinstance(prompt_content, TextContent) else ""
    assert "UNTRUSTED DATA" in text
    assert "aegis://policy/risk" in text


async def health_contract(session: ClientSession) -> None:
    payload = _structured(await session.call_tool("server_health", {}))
    assert payload["version"]
    assert payload["offline"] is True
    assert payload["registered_tools"] == 6
    assert payload["readiness"] is True


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("schema_contract", "Tool surface and annotations are stable", schema_contract),
    Scenario("lookup_known_cve", "Known CVE is enriched and scored", lookup_known_cve),
    Scenario("lookup_missing_cve", "Missing CVE maps to a typed not-found error", lookup_missing_cve),
    Scenario("search_ranks_by_risk", "Search returns risk-ranked structured results", search_ranks_by_risk),
    Scenario("scan_vulnerable_package", "OSV advisory and fixed version are extracted", scan_vulnerable_package),
    Scenario("scan_safe_package", "A clean package returns zero advisories", scan_safe_package),
    Scenario(
        "prompt_injection_is_inert",
        "Feed control characters are stripped and trust is labeled",
        prompt_injection_is_inert,
    ),
    Scenario(
        "triage_complete_and_persisted", "Multi-step triage completes and persists", triage_complete_and_persisted
    ),
    Scenario("triage_is_idempotent", "Identical triage requests reuse the stored report", triage_is_idempotent),
    Scenario(
        "unknown_cve_is_partial_not_failed",
        "Not-found identifiers produce partial coverage",
        unknown_cve_is_partial_not_failed,
    ),
    Scenario("resources_and_prompts", "Policy, catalog, manifest, and prompts are usable", resources_and_prompts),
    Scenario("health_contract", "Runtime status is non-sensitive and accurate", health_contract),
)


async def _run_scenario(scenario: Scenario) -> EvalResult:
    started = time.perf_counter()
    try:
        async with _session() as session:
            await scenario.fn(session)
    except AssertionError as exc:
        detail = str(exc) or "assertion failed"
        passed = False
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        passed = False
    else:
        detail = "ok"
        passed = True
    return EvalResult(
        name=scenario.name,
        passed=passed,
        detail=detail,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


async def run_suite() -> list[EvalResult]:
    results: list[EvalResult] = []
    for scenario in SCENARIOS:
        results.append(await _run_scenario(scenario))
    return results


def _render_text(results: list[EvalResult]) -> str:
    lines = []
    for result in results:
        marker = "PASS" if result.passed else "FAIL"
        lines.append(f"[{marker}] {result.name} ({result.duration_ms} ms)")
        if not result.passed:
            lines.append(f"       {result.detail}")
    passed = sum(1 for result in results if result.passed)
    lines.append(f"\n{passed}/{len(results)} scenarios passed")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis-eval", description="Run deterministic offline evaluations")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)
    results = asyncio.run(run_suite())
    if args.json:
        sys.stdout.write(
            json.dumps(
                {
                    "passed": sum(1 for item in results if item.passed),
                    "total": len(results),
                    "results": [asdict(item) for item in results],
                },
                indent=2,
            )
            + "\n"
        )
    else:
        sys.stdout.write(_render_text(results) + "\n")
    return 0 if all(item.passed for item in results) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
