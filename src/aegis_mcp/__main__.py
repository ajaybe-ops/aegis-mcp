"""Command-line entrypoint: serve, issue development tokens, validate config, run evals."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import jwt
from pydantic import ValidationError

from .config import Settings
from .server import create_http_app, create_server
from .version import __version__


def _build_settings(args: argparse.Namespace) -> Settings:
    overrides: dict[str, object] = {}
    if getattr(args, "host", None):
        overrides["host"] = args.host
    if getattr(args, "port", None):
        overrides["port"] = args.port
    if getattr(args, "transport", None):
        overrides["transport"] = args.transport
    if getattr(args, "log_level", None):
        overrides["log_level"] = args.log_level
    return Settings(**overrides)  # type: ignore[arg-type]


def _config_summary(settings: Settings) -> dict[str, object]:
    """Non-secret configuration for operators and CI smoke checks."""
    return {
        "name": "aegis-mcp",
        "version": __version__,
        "environment": settings.environment,
        "transport": settings.transport,
        "host": settings.host,
        "port": settings.port,
        "mcp_path": settings.mcp_path,
        "public_url": settings.public_url,
        "offline": settings.offline,
        "auth": {
            "mode": settings.auth_mode,
            "algorithms": settings.jwt_algorithms_list,
            "issuer": settings.jwt_issuer,
            "audience": settings.audience,
            "required_scopes": settings.required_scopes_list,
            "secret_configured": settings.jwt_secret is not None,
            "jwks_configured": settings.jwt_jwks_url is not None,
        },
        "limits": {
            "read_rate_per_minute": settings.read_rate_per_minute,
            "read_burst": settings.read_burst,
            "triage_rate_per_minute": settings.triage_rate_per_minute,
            "triage_burst": settings.triage_burst,
            "max_request_body_bytes": settings.max_request_body_bytes,
        },
        "observability": {
            "otel_enabled": settings.otel_enabled,
            "otel_endpoint": settings.otel_endpoint,
            "log_format": settings.log_format,
        },
        "persistence": {"sqlite_path": str(settings.sqlite_path)},
    }


def _cmd_serve(args: argparse.Namespace) -> int:
    settings = _build_settings(args)
    if settings.transport == "streamable-http":
        import uvicorn

        app = create_http_app(settings)
        uvicorn.run(
            app,
            host=settings.host,
            port=settings.port,
            log_config=None,
            access_log=True,
        )
        return 0

    server = create_server(settings)
    asyncio.run(server.run_stdio_async())
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    settings = _build_settings(args)
    sys.stdout.write(json.dumps(_config_summary(settings), indent=2, sort_keys=True) + "\n")
    return 0


def _cmd_token(args: argparse.Namespace) -> int:
    settings = _build_settings(args)
    if settings.is_production:
        sys.stderr.write(
            "refusing to mint development tokens with AEGIS_ENVIRONMENT=production; use your identity provider\n"
        )
        return 2
    if settings.jwt_secret is None:
        sys.stderr.write(
            "no signing secret available: set AEGIS_JWT_SECRET or pass --secret. "
            "JWKS-only deployments must obtain tokens from the identity provider.\n"
        )
        return 2

    secret = args.secret or settings.jwt_secret.get_secret_value()
    if len(secret) < 32:
        sys.stderr.write("the signing secret must contain at least 32 characters\n")
        return 2
    scopes = [item for item in args.scopes.split() if item]
    now = datetime.now(UTC)
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.audience,
        "sub": args.subject,
        "client_id": args.client_id or args.subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=args.ttl)).timestamp()),
        "scope": " ".join(scopes),
    }
    token = jwt.encode(claims, secret, algorithm=settings.jwt_algorithms_list[0])
    sys.stdout.write(token + "\n")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    from .evals.runner import main as eval_main

    return eval_main(["--json"] if args.json else [])


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-mcp",
        description="Aegis MCP server for vulnerability intelligence and incident triage.",
    )
    parser.add_argument("--version", action="version", version=f"aegis-mcp {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    def add_runtime_flags(target: argparse.ArgumentParser) -> None:
        target.add_argument("--host", help="override AEGIS_HOST")
        target.add_argument("--port", type=_positive_int, help="override AEGIS_PORT")
        target.add_argument(
            "--transport",
            choices=["stdio", "streamable-http"],
            help="override AEGIS_TRANSPORT",
        )
        target.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            help="override AEGIS_LOG_LEVEL",
        )

    serve = subparsers.add_parser("serve", help="run the MCP server (default)")
    add_runtime_flags(serve)
    serve.set_defaults(func=_cmd_serve)

    check = subparsers.add_parser("check", help="validate configuration and print non-secret settings")
    add_runtime_flags(check)
    check.set_defaults(func=_cmd_check)

    token = subparsers.add_parser("token", help="mint a development JWT (never for production)")
    add_runtime_flags(token)
    token.add_argument("--subject", default="developer", help="token subject")
    token.add_argument("--client-id", help="OAuth client id (defaults to the subject)")
    token.add_argument("--scopes", default="aegis:read aegis:triage", help="space-separated scopes")
    token.add_argument("--ttl", type=_positive_int, default=3_600, help="token lifetime in seconds")
    token.add_argument("--secret", help="signing secret (prefer AEGIS_JWT_SECRET)")
    token.set_defaults(func=_cmd_token)

    eval_parser = subparsers.add_parser("eval", help="run the deterministic offline evaluation suite")
    eval_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    eval_parser.set_defaults(func=_cmd_eval)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None) is None:
        args = parser.parse_args(["serve", *(argv or ())])
    try:
        result: int = args.func(args)
    except ValidationError as exc:
        sys.stderr.write(f"invalid configuration:\n{exc}\n")
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        return 130
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
