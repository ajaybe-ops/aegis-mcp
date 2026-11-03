"""MCP resources: policy, source catalog, runtime manifest, and incident reports."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError

from ..domain.errors import AegisError
from ..domain.risk import policy_document
from ..domain.sanitize import validate_incident_id
from ..intel.sources import catalog_document
from ..version import __version__

if TYPE_CHECKING:
    from ..server import ServerRuntime


def _json(document: Any) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str)


def register_resources(mcp: MCPServer[Any], runtime: ServerRuntime) -> int:
    @mcp.resource(
        "aegis://policy/risk",
        name="risk-policy",
        title="Aegis risk scoring policy",
        description=(
            "Machine-readable risk model: weights, asset points, KEV floor, band thresholds, and limitations. "
            "Read this before interpreting a score."
        ),
        mime_type="application/json",
    )
    def risk_policy() -> str:
        return _json(policy_document())

    @mcp.resource(
        "aegis://catalog/sources",
        name="source-catalog",
        title="Upstream intelligence source catalog",
        description="Endpoints, licenses, attribution, cache TTLs, and trust classification for every upstream feed.",
        mime_type="application/json",
    )
    def source_catalog() -> str:
        return _json(catalog_document())

    @mcp.resource(
        "aegis://server/manifest",
        name="server-manifest",
        title="Aegis server manifest",
        description="Non-secret capabilities, authorization scopes, limits, and data-handling contract.",
        mime_type="application/json",
    )
    def manifest() -> str:
        settings = runtime.settings
        return _json(
            {
                "name": "aegis-mcp",
                "version": __version__,
                "transport": settings.transport,
                "environment": settings.environment,
                "offline": settings.offline,
                "authorization": {
                    "mode": settings.auth_mode,
                    "bearer_required": settings.auth_mode == "jwt",
                    "transport_scopes": settings.required_scopes_list,
                    "tool_scopes": {
                        "read": ["aegis:read"],
                        "triage": ["aegis:read", "aegis:triage"],
                    },
                },
                "limits": {
                    "max_request_body_bytes": settings.max_request_body_bytes,
                    "read_rate_per_minute": settings.read_rate_per_minute,
                    "read_burst": settings.read_burst,
                    "triage_rate_per_minute": settings.triage_rate_per_minute,
                    "triage_burst": settings.triage_burst,
                    "max_cves_per_call": 20,
                    "max_packages_per_call": 20,
                    "max_assets_per_incident": 50,
                    "triage_deadline_seconds_max": 25,
                },
                "data_handling": {
                    "external_content": "untrusted; sanitized; never executed",
                    "persistence": "triage reports only, SQLite",
                    "secrets_in_resources": False,
                },
            }
        )

    @mcp.resource(
        "aegis://incidents/{incident_id}",
        name="incident-report",
        title="Persisted incident triage report",
        description="Latest JSON report for an incident id created by triage_incident.",
        mime_type="application/json",
    )
    async def incident_report(incident_id: str) -> str:
        try:
            validated = validate_incident_id(incident_id)
        except AegisError as exc:
            raise ResourceError(exc.public_message()) from exc
        report = await runtime.store.get(validated)
        if report is None:
            raise ResourceError(f"no triage report exists for incident {validated}")
        return report.model_dump_json(indent=2)

    return 4
