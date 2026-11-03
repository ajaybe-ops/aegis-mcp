"""CLI smoke tests: config validation output, token minting, and eval dispatch."""

from __future__ import annotations

import json

import jwt
import pytest

from aegis_mcp.__main__ import main
from aegis_mcp.version import __version__


def _isolate_env(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_ENVIRONMENT", "development")
    monkeypatch.setenv("AEGIS_TRANSPORT", "stdio")
    monkeypatch.setenv("AEGIS_AUTH_MODE", "local")
    monkeypatch.setenv("AEGIS_OFFLINE", "true")
    monkeypatch.setenv("AEGIS_OTEL_ENABLED", "false")
    monkeypatch.setenv("AEGIS_LOG_LEVEL", "ERROR")
    monkeypatch.setenv("AEGIS_LOG_FORMAT", "console")
    monkeypatch.setenv("AEGIS_SQLITE_PATH", ":memory:")
    monkeypatch.setenv("AEGIS_PUBLIC_URL", "http://localhost:8000")
    monkeypatch.setenv("AEGIS_JWT_ISSUER", "https://issuer.example.test")


def test_check_prints_non_secret_config(monkeypatch, capsys, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    _isolate_env(monkeypatch)
    assert main(["check"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "aegis-mcp"
    assert payload["version"] == __version__
    assert payload["auth"]["mode"] == "local"
    assert payload["auth"]["secret_configured"] is False


def test_token_mint_round_trip(monkeypatch, capsys) -> None:
    _isolate_env(monkeypatch)
    monkeypatch.setenv("AEGIS_AUTH_MODE", "jwt")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "cli-test-secret-with-more-than-32-chars")
    monkeypatch.setenv("AEGIS_JWT_ISSUER", "https://issuer.example.test")
    monkeypatch.setenv("AEGIS_PUBLIC_URL", "https://aegis.example.test")
    assert main(["token", "--subject", "ci-bot"]) == 0
    token = capsys.readouterr().out.strip()
    claims = jwt.decode(
        token, "cli-test-secret-with-more-than-32-chars", algorithms=["HS256"], audience="https://aegis.example.test"
    )
    assert claims["sub"] == "ci-bot"
    assert "aegis:read" in claims["scope"]


def test_token_refuses_production(monkeypatch, capsys) -> None:
    _isolate_env(monkeypatch)
    monkeypatch.setenv("AEGIS_ENVIRONMENT", "production")
    monkeypatch.setenv("AEGIS_AUTH_MODE", "jwt")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "cli-test-secret-with-more-than-32-chars")
    monkeypatch.setenv("AEGIS_PUBLIC_URL", "https://aegis.example.test")
    assert main(["token"]) == 2
    assert "identity provider" in capsys.readouterr().err


def test_streamable_http_without_auth_is_rejected(monkeypatch, capsys) -> None:
    _isolate_env(monkeypatch)
    assert main(["check", "--transport", "streamable-http"]) == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_version_flag_exits(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
