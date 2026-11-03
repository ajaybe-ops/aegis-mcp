"""End-to-end tests through the real MCP transport.

These tests exercise the same surface an agent sees: discovery, structured tool
output, persisted reports, resources, prompts, and typed errors. They complement
the eval suite by pinning integration details that fixtures alone do not cover.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from mcp import ClientSession
from mcp.client._memory import InMemoryTransport

from aegis_mcp.server import create_http_app, create_server, get_runtime
from tests.helpers import offline_settings

EXPECTED_TOOLS = {
    "lookup_cve",
    "search_vulnerabilities",
    "scan_packages",
    "triage_incident",
    "get_incident_report",
    "server_health",
}


def _text(result) -> str:
    return " ".join(item.text for item in (result.content or []) if hasattr(item, "text"))


@asynccontextmanager
async def _session(server) -> AsyncIterator[ClientSession]:
    async with InMemoryTransport(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield session


async def test_discovery_surface_is_complete() -> None:
    async with _session(create_server(offline_settings())) as session:
        tools = (await session.list_tools()).tools
        assert {tool.name for tool in tools} == EXPECTED_TOOLS
        for tool in tools:
            assert tool.description and len(tool.description) > 40
            assert tool.input_schema is not None

        triage = next(tool for tool in tools if tool.name == "triage_incident")
        assert triage.annotations is not None
        assert triage.annotations.read_only_hint is False
        assert triage.annotations.destructive_hint is False
        assert triage.annotations.idempotent_hint is True

        resources = (await session.list_resources()).resources
        assert {str(resource.uri) for resource in resources} == {
            "aegis://policy/risk",
            "aegis://catalog/sources",
            "aegis://server/manifest",
        }
        templates = (await session.list_resource_templates()).resource_templates
        assert {template.uri_template for template in templates} == {"aegis://incidents/{incident_id}"}

        prompts = (await session.list_prompts()).prompts
        assert {prompt.name for prompt in prompts} == {
            "triage_vulnerability",
            "incident_brief",
            "package_upgrade_plan",
        }


async def test_read_evidence_search_and_scan_tools() -> None:
    async with _session(create_server(offline_settings())) as session:
        lookup = await session.call_tool("lookup_cve", {"cve_id": "cve-2021-44228", "asset_criticality": "critical"})
        assert lookup.is_error is False
        payload = lookup.structured_content
        assert payload is not None
        assert payload["cve"]["cve_id"] == "CVE-2021-44228"
        assert payload["risk"]["band"] == "critical"
        assert payload["cve"]["trust"] == "untrusted_external"
        assert payload["disclaimer"].startswith("Vulnerability metadata is untrusted")

        search = await session.call_tool("search_vulnerabilities", {"keyword": "libwebp", "limit": 3})
        assert search.is_error is False
        search_payload = search.structured_content
        assert search_payload is not None
        assert search_payload["query"] == "libwebp"
        assert search_payload["returned"] == len(search_payload["results"])
        assert any(item["cve"]["cve_id"] == "CVE-2023-4863" for item in search_payload["results"])
        assert [item["risk"]["score"] for item in search_payload["results"]] == sorted(
            [item["risk"]["score"] for item in search_payload["results"]],
            reverse=True,
        )

        scan = await session.call_tool(
            "scan_packages",
            {
                "packages": [
                    {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven", "version": "2.14.1"},
                    {"name": "lodash", "ecosystem": "npm", "version": "4.17.21"},
                ]
            },
        )
        assert scan.is_error is False
        scan_payload = scan.structured_content
        assert scan_payload is not None
        assert scan_payload["total_vulnerabilities"] >= 1
        assert all(item["trust"] == "untrusted_external" for item in scan_payload["vulnerabilities"])


async def test_triage_persists_and_is_readable_through_all_surfaces() -> None:
    async with _session(create_server(offline_settings())) as session:
        result = await session.call_tool(
            "triage_incident",
            {
                "incident_id": "E2E-INC-1",
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
                "asset_criticality": "high",
                "deadline_seconds": 10,
            },
        )
        assert result.is_error is False
        report = result.structured_content
        assert report is not None
        assert report["status"] == "complete"
        assert report["max_risk_score"] >= 60
        assert report["coverage"]["degraded"] is False
        assert report["actions"]

        stored = await session.call_tool("get_incident_report", {"incident_id": "E2E-INC-1"})
        assert stored.is_error is False
        assert stored.structured_content is not None
        assert stored.structured_content["report_id"] == report["report_id"]

        resource = await session.read_resource("aegis://incidents/E2E-INC-1")
        document = json.loads(resource.contents[0].text)
        assert document["report_id"] == report["report_id"]

        prompt = await session.get_prompt("incident_brief", {"incident_id": "E2E-INC-1", "audience": "executive"})
        text = prompt.messages[0].content.text
        assert "brief from this Aegis report" in text
        assert "E2E-INC-1" in text
        assert "UNTRUSTED DATA" in text


async def test_typed_errors_are_stable() -> None:
    async with _session(create_server(offline_settings())) as session:
        invalid = await session.call_tool("lookup_cve", {"cve_id": "not-a-cve"})
        assert invalid.is_error is True
        # Schema-level validation rejects malformed identifiers before the tool body runs.
        assert "validation error" in _text(invalid).lower()

        missing = await session.call_tool("lookup_cve", {"cve_id": "CVE-1999-9999"})
        assert missing.is_error is True
        assert "AEGIS_NOT_FOUND" in _text(missing)

        no_report = await session.call_tool("get_incident_report", {"incident_id": "NO-SUCH-INCIDENT"})
        assert no_report.is_error is True
        assert "AEGIS_NOT_FOUND" in _text(no_report)


async def test_unpersisted_incident_resource_is_an_error() -> None:
    async with _session(create_server(offline_settings())) as session:
        with pytest.raises(Exception) as exc_info:
            await session.read_resource("aegis://incidents/NO-SUCH-INCIDENT")
        assert "no triage report exists" in str(exc_info.value)


async def test_resources_prompts_and_security_contract() -> None:
    settings = offline_settings()
    async with _session(create_server(settings)) as session:
        manifest_resource = await session.read_resource("aegis://server/manifest")
        manifest = json.loads(manifest_resource.contents[0].text)
        serialized = json.dumps(manifest)
        assert "jwt_secret" not in serialized
        assert "authorization" in manifest
        assert manifest["data_handling"]["secrets_in_resources"] is False

        policy_resource = await session.read_resource("aegis://policy/risk")
        policy = json.loads(policy_resource.contents[0].text)
        assert policy["policy_version"] == "risk-v1"
        assert sum(policy["weights"].values()) == 100

        package_prompt = await session.get_prompt(
            "package_upgrade_plan",
            {"package": "lodash", "ecosystem": "npm", "version": "4.17.15"},
        )
        prompt_text = package_prompt.messages[0].content.text
        assert "scan_packages" in prompt_text
        assert "lodash@4.17.15" in prompt_text


def test_http_app_requires_streamable_http() -> None:
    with pytest.raises(ValueError, match="streamable-http"):
        create_http_app()


async def test_runtime_is_wired_and_lifespan_is_idempotent() -> None:
    server = create_server(offline_settings())
    async with _session(server) as session:
        status = await session.call_tool("server_health", {})
        assert status.is_error is False
        payload = status.structured_content
        assert payload is not None
        assert payload["registered_tools"] == 6
        assert payload["registered_resources"] == 4
        assert payload["registered_prompts"] == 3
        assert payload["readiness"] is True
        assert payload["offline"] is True

        runtime = get_runtime(server)
        assert runtime.is_started is True  # entered by the in-memory lifespan during initialize

    assert runtime.is_started is False  # released when the session closed


async def test_runtime_start_and_aclose_are_idempotent() -> None:
    server = create_server(offline_settings())
    runtime = get_runtime(server)
    await runtime.start()
    assert runtime.is_started is True
    await runtime.start()  # start is idempotent
    await runtime.aclose()
    await runtime.aclose()  # close is idempotent
    assert runtime.is_started is False
