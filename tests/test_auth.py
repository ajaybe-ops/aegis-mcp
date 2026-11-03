"""JWT verification, local principals, scope checks, and the tool guard."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver.exceptions import ToolError

from aegis_mcp.config import Settings
from aegis_mcp.domain.errors import AuthzError
from aegis_mcp.infra.telemetry import configure_observability
from aegis_mcp.security.auth import AuthService, JWTTokenVerifier
from aegis_mcp.security.guard import ToolGuard
from aegis_mcp.security.limits import LimitPolicy, TokenBucketRateLimiter

SECRET = "test-secret-with-more-than-32-characters"


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "environment": "test",
        "transport": "stdio",
        "auth_mode": "jwt",
        "jwt_secret": SECRET,
        "jwt_issuer": "https://issuer.example.test",
        "public_url": "https://aegis.example.test",
        "offline": True,
        "otel_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def _token(**claims: object) -> str:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "iss": "https://issuer.example.test",
        "aud": "https://aegis.example.test",
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "scope": "aegis:read aegis:triage",
    }
    payload.update(claims)
    return jwt.encode(payload, SECRET, algorithm="HS256")


async def test_valid_token_returns_access_token() -> None:
    verifier = JWTTokenVerifier(_settings())
    token = _token()
    access = await verifier.verify_token(token)
    assert access is not None
    assert access.subject == "user-1"
    assert access.client_id == "client-1"
    assert access.scopes == ["aegis:read", "aegis:triage"]
    assert access.resource == "https://aegis.example.test"


async def test_scp_list_claim_is_supported() -> None:
    verifier = JWTTokenVerifier(_settings())
    token = _token(scope=None, scp=["aegis:read", "custom"])
    access = await verifier.verify_token(token)
    assert access is not None
    assert set(access.scopes) == {"aegis:read", "custom"}


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "https://other.example.test"},
        {"iss": "https://evil.example.test"},
        {"exp": int(datetime.now(UTC).timestamp()) - 120},
        {"sub": ""},
        {"sub": None},
    ],
)
async def test_invalid_claims_are_rejected(claims: dict[str, object]) -> None:
    verifier = JWTTokenVerifier(_settings())
    assert await verifier.verify_token(_token(**claims)) is None


async def test_tampered_and_garbage_tokens_are_rejected() -> None:
    verifier = JWTTokenVerifier(_settings())
    token = _token()
    assert await verifier.verify_token(token + "x") is None
    assert await verifier.verify_token("not-a-token") is None
    assert await verifier.verify_token("") is None
    assert await verifier.verify_token("x" * 9_000) is None


async def test_missing_required_claim_is_rejected() -> None:
    verifier = JWTTokenVerifier(_settings())
    token = jwt.encode({"sub": "user-1"}, SECRET, algorithm="HS256")
    assert await verifier.verify_token(token) is None


def test_local_principal_has_configured_scopes() -> None:
    service = AuthService(_settings(auth_mode="local", transport="stdio"))
    principal = service.current_principal()
    assert principal.method == "local"
    assert principal.subject == "local-stdio"
    assert principal.scopes == frozenset({"aegis:read", "aegis:triage"})


def test_jwt_mode_without_token_is_denied() -> None:
    service = AuthService(_settings())
    with pytest.raises(AuthzError, match="authentication required"):
        service.current_principal()


def test_principal_is_built_from_access_token_context() -> None:
    service = AuthService(_settings())
    token = AccessToken(
        token="raw",
        client_id="client-1",
        scopes=["aegis:read"],
        subject="user-1",
        claims={"iss": "https://issuer.example.test"},
    )
    reset = auth_context_var.set(AuthenticatedUser(token))
    try:
        principal = service.current_principal()
    finally:
        auth_context_var.reset(reset)
    assert principal.method == "jwt"
    assert principal.subject == "user-1"
    assert principal.issuer == "https://issuer.example.test"
    assert principal.limiter_key == principal.limiter_key
    assert len(principal.limiter_key) == 32


def test_require_scope() -> None:
    service = AuthService(_settings(auth_mode="local", transport="stdio"))
    principal = service.current_principal()
    service.require(principal, "aegis:read")
    with pytest.raises(AuthzError, match="aegis:admin"):
        service.require(principal, "aegis:read", "aegis:triage", "aegis:admin")


def _guard(settings: Settings) -> ToolGuard:
    telemetry = configure_observability(settings)
    limiter = TokenBucketRateLimiter()
    limiter.configure("read", LimitPolicy(rate_per_minute=60, burst=2))
    limiter.configure("triage", LimitPolicy(rate_per_minute=60, burst=1))
    return ToolGuard(auth=AuthService(settings), limiter=limiter, telemetry=telemetry)


async def test_guard_allows_local_principal() -> None:
    guard = _guard(_settings(auth_mode="local", transport="stdio"))

    async def work() -> str:
        return "ok"

    assert await guard.call("lookup_cve", work, scopes=("aegis:read",), rate_class="read") == "ok"


async def test_guard_denies_missing_scope() -> None:
    guard = _guard(_settings())
    token = AccessToken(token="raw", client_id="c", scopes=["aegis:read"], subject="u")
    reset = auth_context_var.set(AuthenticatedUser(token))
    try:
        with pytest.raises(ToolError, match="AEGIS_FORBIDDEN"):
            await guard.call("triage_incident", _never, scopes=("aegis:read", "aegis:triage"), rate_class="triage")
    finally:
        auth_context_var.reset(reset)


async def test_guard_rate_limits() -> None:
    guard = _guard(_settings())
    token = AccessToken(token="raw", client_id="c", scopes=["aegis:read", "aegis:triage"], subject="u")
    reset = auth_context_var.set(AuthenticatedUser(token))
    try:
        await guard.call("triage_incident", _ok, scopes=("aegis:triage",), rate_class="triage")
        with pytest.raises(ToolError, match="AEGIS_RATE_LIMITED"):
            await guard.call("triage_incident", _ok, scopes=("aegis:triage",), rate_class="triage")
    finally:
        auth_context_var.reset(reset)


async def test_guard_converts_anticipated_error() -> None:
    guard = _guard(_settings(auth_mode="local", transport="stdio"))
    with pytest.raises(ToolError, match="AEGIS_NOT_FOUND"):
        await guard.call("get_incident_report", _not_found, scopes=("aegis:read",), rate_class="read")


async def test_guard_does_not_swallow_crashes() -> None:
    guard = _guard(_settings(auth_mode="local", transport="stdio"))
    with pytest.raises(ValueError, match="boom"):
        await guard.call("lookup_cve", _crash, scopes=("aegis:read",), rate_class="read")


async def _ok() -> str:
    return "ok"


async def _never() -> str:  # pragma: no cover - must not execute
    raise AssertionError("should not run")


async def _not_found() -> str:
    from aegis_mcp.domain.errors import NotFoundError

    raise NotFoundError("missing")


async def _crash() -> str:
    raise ValueError("boom")
