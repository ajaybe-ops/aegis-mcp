"""Configuration is a security boundary; these tests pin fail-closed behavior."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis_mcp.config import Settings


def _settings(**overrides: object) -> Settings:
    values = {"_env_file": None, "offline": True, "otel_enabled": False}
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_defaults_are_local_stdio() -> None:
    settings = _settings()
    assert settings.transport == "stdio"
    assert settings.auth_mode == "local"
    assert settings.audience == settings.public_url
    assert settings.required_scopes_list == ["aegis:read"]
    assert settings.jwt_algorithms_list == ["HS256"]


def test_http_requires_authentication() -> None:
    with pytest.raises(ValidationError, match="without authentication"):
        _settings(transport="streamable-http", auth_mode="local")


def test_local_auth_is_stdio_only() -> None:
    with pytest.raises(ValidationError, match="local authentication"):
        _settings(transport="streamable-http", auth_mode="local")


def test_jwt_requires_a_key() -> None:
    with pytest.raises(ValidationError, match="requires AEGIS_JWT_SECRET"):
        _settings(auth_mode="jwt")


def test_jwt_secret_length_is_enforced() -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        _settings(auth_mode="jwt", jwt_secret="short")


def test_none_algorithm_is_forbidden() -> None:
    with pytest.raises(ValidationError, match="none"):
        _settings(auth_mode="jwt", jwt_secret="x" * 40, jwt_algorithms="none")


def test_empty_algorithm_list_is_rejected() -> None:
    with pytest.raises(ValidationError, match="at least one algorithm"):
        _settings(auth_mode="jwt", jwt_secret="x" * 40, jwt_algorithms=" , ")


def test_jwks_must_use_https_off_localhost() -> None:
    with pytest.raises(ValidationError, match="https"):
        _settings(auth_mode="jwt", jwt_jwks_url="http://idp.example.test/jwks")


def test_local_http_jwks_is_allowed_for_development() -> None:
    settings = _settings(auth_mode="jwt", jwt_jwks_url="http://localhost:8080/jwks")
    assert settings.jwt_jwks_url == "http://localhost:8080/jwks"


def test_production_requires_tls_public_url() -> None:
    with pytest.raises(ValidationError, match="https public_url"):
        _settings(
            environment="production",
            transport="streamable-http",
            auth_mode="jwt",
            jwt_secret="x" * 40,
            public_url="http://aegis.example.test",
        )


def test_production_accepts_https_and_secret() -> None:
    settings = _settings(
        environment="production",
        transport="streamable-http",
        auth_mode="jwt",
        jwt_secret="x" * 40,
        public_url="https://aegis.example.test",
        allowed_hosts="aegis.example.test",
    )
    assert settings.is_production
    assert settings.public_url == "https://aegis.example.test"


def test_urls_reject_embedded_credentials() -> None:
    with pytest.raises(ValidationError, match="credentials"):
        _settings(public_url="https://user:pass@aegis.example.test")


def test_urls_reject_non_http_schemes() -> None:
    with pytest.raises(ValidationError, match="absolute http"):
        _settings(public_url="ftp://aegis.example.test")


def test_mcp_path_validation() -> None:
    with pytest.raises(ValidationError, match="absolute URL path"):
        _settings(mcp_path="mcp")
    with pytest.raises(ValidationError, match="query or fragment"):
        _settings(mcp_path="/mcp?x=1")


def test_sqlite_extension_validation(tmp_path) -> None:
    with pytest.raises(ValidationError, match="sqlite_path"):
        _settings(sqlite_path=tmp_path / "aegis.txt")
    assert str(_settings(sqlite_path=":memory:").sqlite_path) == ":memory:"


def test_retry_window_validation() -> None:
    with pytest.raises(ValidationError, match="retry_max_delay_seconds"):
        _settings(retry_base_delay_seconds=2.0, retry_max_delay_seconds=1.0)


def test_derived_lists_and_audience() -> None:
    settings = _settings(
        required_scopes="aegis:read, aegis:triage ,",
        allowed_hosts="a.example, b.example: *",
        jwt_audience="https://api.example.test/mcp",
    )
    assert settings.required_scopes_list == ["aegis:read", "aegis:triage"]
    assert settings.allowed_hosts_list == ["a.example", "b.example: *"]
    assert settings.audience == "https://api.example.test/mcp"


def test_secret_is_not_in_repr() -> None:
    settings = _settings(auth_mode="jwt", jwt_secret="s" * 40)
    assert "s" * 40 not in repr(settings)
