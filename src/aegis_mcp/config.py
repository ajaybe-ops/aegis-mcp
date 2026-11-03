"""Typed, environment-driven configuration with fail-fast production guards."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
Transport = Literal["stdio", "streamable-http"]
AuthMode = Literal["local", "jwt"]
LogFormat = Literal["json", "console"]


class Settings(BaseSettings):
    """All runtime configuration.

    Secrets are wrapped in ``SecretStr`` so accidental ``repr``/logging cannot expose
    them. Configuration is validated once at startup; invalid security combinations
    fail closed instead of degrading silently.
    """

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- process / transport -------------------------------------------------
    environment: Environment = "development"
    transport: Transport = "stdio"
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    mcp_path: str = "/mcp"
    public_url: str = "http://localhost:8000"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: LogFormat = "json"
    max_request_body_bytes: int = Field(default=524_288, ge=16_384, le=8 * 1024 * 1024)

    # --- authentication / authorization -------------------------------------
    auth_mode: AuthMode = "local"
    jwt_secret: SecretStr | None = None
    jwt_algorithms: str = "HS256"
    jwt_issuer: str = "https://aegis.local"
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    jwt_leeway_seconds: int = Field(default=30, ge=0, le=300)
    required_scopes: str = "aegis:read"
    local_scopes: str = "aegis:read,aegis:triage"
    allowed_hosts: str = "localhost:*,127.0.0.1:*,[::1]:*"
    allowed_origins: str = "http://localhost:*,http://127.0.0.1:*,http://[::1]:*"

    # --- rate limiting / concurrency ----------------------------------------
    read_rate_per_minute: int = Field(default=60, ge=1, le=10_000)
    read_burst: int = Field(default=15, ge=1, le=1_000)
    triage_rate_per_minute: int = Field(default=10, ge=1, le=1_000)
    triage_burst: int = Field(default=3, ge=1, le=100)
    max_upstream_concurrency: int = Field(default=8, ge=1, le=64)
    max_triage_concurrency: int = Field(default=5, ge=1, le=20)

    # --- outbound HTTP resilience -------------------------------------------
    upstream_timeout_seconds: float = Field(default=8.0, gt=0, le=60)
    upstream_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    max_retries: int = Field(default=3, ge=0, le=8)
    retry_base_delay_seconds: float = Field(default=0.15, ge=0, le=5)
    retry_max_delay_seconds: float = Field(default=2.0, ge=0, le=30)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    circuit_reset_seconds: float = Field(default=30.0, gt=0, le=600)
    max_upstream_response_bytes: int = Field(default=2_000_000, ge=1_024, le=50 * 1024 * 1024)
    nvd_api_key: SecretStr | None = None
    cache_ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    kev_cache_ttl_seconds: int = Field(default=3_600, ge=60, le=86_400)
    cache_max_entries: int = Field(default=2_048, ge=16, le=100_000)
    user_agent: str = "aegis-mcp/0.1.0 (+https://github.com/example/aegis-mcp)"

    # --- persistence ---------------------------------------------------------
    sqlite_path: Path = Path("data/aegis.db")

    # --- observability -------------------------------------------------------
    otel_enabled: bool = True
    otel_endpoint: str | None = None
    otel_service_name: str = "aegis-mcp"
    otel_console_export: bool = False

    # --- deterministic offline mode (tests / evals / air-gapped demos) ------
    offline: bool = False

    @field_validator("mcp_path")
    @classmethod
    def _valid_path(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value:
            raise ValueError("mcp_path must be an absolute URL path without query or fragment")
        return value

    @field_validator("public_url", "jwt_issuer", "jwt_jwks_url", "otel_endpoint")
    @classmethod
    def _valid_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"expected an absolute http(s) URL, got {value!r}")
        if parsed.username or parsed.password:
            raise ValueError("URLs must not contain embedded credentials")
        return value.rstrip("/") if parsed.path in {"", "/"} else value

    @field_validator("sqlite_path")
    @classmethod
    def _valid_db_path(cls, value: Path) -> Path:
        if str(value) == ":memory:":
            return value
        if value.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
            raise ValueError("sqlite_path must end in .db, .sqlite, or .sqlite3")
        return value

    @model_validator(mode="after")
    def _security_invariants(self) -> Self:
        if self.transport == "streamable-http":
            if self.auth_mode == "local":
                raise ValueError(
                    "refusing to expose streamable-http without authentication: local "
                    "authentication is only permitted for stdio transports; set "
                    "AEGIS_AUTH_MODE=jwt and configure AEGIS_JWT_SECRET or AEGIS_JWT_JWKS_URL"
                )
            if self.environment == "production" and urlparse(self.public_url).scheme != "https":
                raise ValueError("production deployments must expose an https public_url (TLS terminates at the proxy)")
            if self.environment == "production" and self.jwt_jwks_url is None and self.jwt_secret is None:
                raise ValueError("production JWT mode requires AEGIS_JWT_JWKS_URL or AEGIS_JWT_SECRET")

        if self.auth_mode == "jwt":
            if not self.jwt_secret and not self.jwt_jwks_url:
                raise ValueError("jwt auth_mode requires AEGIS_JWT_SECRET or AEGIS_JWT_JWKS_URL")
            if self.jwt_secret is not None and len(self.jwt_secret.get_secret_value()) < 32:
                raise ValueError("AEGIS_JWT_SECRET must contain at least 32 bytes of entropy")
            algorithms = set(self.jwt_algorithms_list)
            if not algorithms:
                raise ValueError("AEGIS_JWT_ALGORITHMS must contain at least one algorithm")
            if "NONE" in algorithms:
                raise ValueError("the 'none' JWT algorithm is forbidden")
            if self.jwt_jwks_url is not None and urlparse(self.jwt_jwks_url).scheme != "https":
                host = urlparse(self.jwt_jwks_url).hostname or ""
                if host not in {"localhost", "127.0.0.1", "::1"}:
                    raise ValueError("AEGIS_JWT_JWKS_URL must use https unless it points at localhost")
        if self.auth_mode == "local" and self.transport != "stdio":
            raise ValueError("local authentication is only permitted for stdio transports")

        if self.retry_max_delay_seconds < self.retry_base_delay_seconds:
            raise ValueError("retry_max_delay_seconds must be >= retry_base_delay_seconds")
        if self.port == 0 and self.transport == "streamable-http":
            raise ValueError("a fixed port is required for streamable-http")
        return self

    # --- derived helpers -----------------------------------------------------
    @property
    def jwt_algorithms_list(self) -> list[str]:
        return [item.strip().upper() for item in self.jwt_algorithms.split(",") if item.strip()]

    @property
    def required_scopes_list(self) -> list[str]:
        return [item.strip() for item in self.required_scopes.split(",") if item.strip()]

    @property
    def local_scopes_list(self) -> list[str]:
        return [item.strip() for item in self.local_scopes.split(",") if item.strip()]

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_hosts.split(",") if item.strip()]

    @property
    def allowed_origins_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]

    @property
    def audience(self) -> str:
        return self.jwt_audience or self.public_url

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton (safe because configuration is immutable at runtime)."""
    return Settings()
