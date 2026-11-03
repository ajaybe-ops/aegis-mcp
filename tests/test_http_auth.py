"""Streamable-HTTP surface: unauthenticated, invalid-token, and scope enforcement."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from mcp.types import LATEST_PROTOCOL_VERSION
from starlette.testclient import TestClient

from aegis_mcp.config import Settings
from aegis_mcp.server import create_http_app

SECRET = "test-secret-with-more-than-32-characters"
ISSUER = "https://issuer.example.test"
AUDIENCE = "https://aegis.example.test"
READ_SCOPES = "aegis:read"
TRIAGE_SCOPES = "aegis:read aegis:triage"


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "transport": "streamable-http",
        "auth_mode": "jwt",
        "jwt_secret": SECRET,
        "jwt_issuer": ISSUER,
        "public_url": AUDIENCE,
        "offline": True,
        "otel_enabled": False,
        "log_level": "ERROR",
        "log_format": "console",
        "sqlite_path": ":memory:",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def _token(scopes: str = READ_SCOPES, **claims: object) -> str:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "scope": scopes,
    }
    payload.update(claims)
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _initialize_body() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "aegis-test-client", "version": "0.0.0"},
        },
    }


@pytest.fixture
def client() -> TestClient:
    app = create_http_app(_settings())
    with TestClient(app, base_url="http://localhost:8000") as test_client:
        yield test_client


def test_health_endpoints_are_unauthenticated() -> None:
    with TestClient(create_http_app(_settings())) as unauth_client:
        assert unauth_client.get("/healthz").status_code == 200
        assert unauth_client.get("/readyz").status_code == 200
        assert unauth_client.get("/healthz").json()["status"] == "ok"


def test_mcp_endpoint_rejects_missing_token(client: TestClient) -> None:
    response = client.post("/mcp", json=_initialize_body())
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert "Bearer" in response.headers["www-authenticate"]


def test_mcp_endpoint_rejects_malformed_token(client: TestClient) -> None:
    response = client.post("/mcp", json=_initialize_body(), headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


def test_mcp_endpoint_rejects_wrong_audience(client: TestClient) -> None:
    token = _token(aud="https://other.example.test")
    response = client.post("/mcp", json=_initialize_body(), headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_mcp_endpoint_rejects_token_without_required_scope(client: TestClient) -> None:
    token = _token(scopes="aegis:triage")
    response = client.post("/mcp", json=_initialize_body(), headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"
    assert "aegis:read" in response.text


def test_mcp_endpoint_accepts_valid_token_and_initializes(client: TestClient) -> None:
    token = _token()
    response = client.post(
        "/mcp",
        json=_initialize_body(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    assert "serverInfo" in response.text


def test_healthz_body_is_json_and_non_sensitive() -> None:
    with TestClient(create_http_app(_settings())) as unauth_client:
        response = unauth_client.get("/healthz")
        body = response.json()
        assert body == {
            "status": "ok",
            "service": "aegis-mcp",
            "version": body["version"],
        }
        assert body["version"]
        assert "secret" not in json.dumps(body).lower()
