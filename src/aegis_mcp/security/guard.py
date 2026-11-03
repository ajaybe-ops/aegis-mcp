"""Cross-cutting tool guard: authorization, rate limiting, spans, metrics, logs."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.context import CallNext, HandlerResult, ServerMiddleware, ServerRequestContext
from mcp.server.mcpserver.exceptions import ToolError

from ..domain.errors import AegisError, RateLimitError
from ..infra.logging import principal_var, request_id_var, tool_var
from ..infra.telemetry import Observability
from .auth import AuthService
from .limits import TokenBucketRateLimiter

logger = logging.getLogger(__name__)

R = TypeVar("R")


class ToolGuard:
    """Explicit guard used by every tool body.

    A decorator was intentionally avoided: wrapping an async function that uses
    postponed annotations complicates signature/context resolution in the SDK.
    Calling ``guard.call`` is one line and keeps schemas derived from the real
    function.
    """

    def __init__(
        self,
        *,
        auth: AuthService,
        limiter: TokenBucketRateLimiter,
        telemetry: Observability,
    ) -> None:
        self._auth = auth
        self._limiter = limiter
        self._telemetry = telemetry

    async def call(
        self,
        tool_name: str,
        fn: Callable[[], Awaitable[R]],
        *,
        scopes: tuple[str, ...],
        rate_class: str,
    ) -> R:
        started = time.perf_counter()
        try:
            principal = self._auth.current_principal()
            self._auth.require(principal, *scopes)
            await self._limiter.acquire(principal.limiter_key, rate_class)
        except AegisError as exc:
            outcome = "unauthorized" if exc.code == "AEGIS_FORBIDDEN" else "rate_limited"
            self._telemetry.tool_calls.add(1, {"tool": tool_name, "outcome": outcome})
            if isinstance(exc, RateLimitError):
                self._telemetry.rate_limit_rejections.add(1, {"tool": tool_name})
            else:
                self._telemetry.auth_denials.add(1, {"tool": tool_name})
            logger.warning(
                "tool authorization or limit failure",
                extra={"tool": tool_name, "outcome": outcome, "duration_ms": 0},
            )
            raise ToolError(exc.public_message()) from exc

        attributes = {
            "aegis.tool.name": tool_name,
            "aegis.principal": principal.subject,
            "aegis.auth.method": principal.method,
            "aegis.required.scopes": ",".join(scopes),
        }
        with self._telemetry.span(f"tool.{tool_name}", attributes) as span:
            try:
                result = await fn()
            except AegisError as exc:
                self._telemetry.tool_calls.add(1, {"tool": tool_name, "outcome": "error"})
                span.set_attribute("aegis.error.code", exc.code)
                logger.warning(
                    "anticipated tool failure",
                    extra={
                        "tool": tool_name,
                        "outcome": "error",
                        "duration_ms": int((time.perf_counter() - started) * 1000),
                    },
                )
                raise ToolError(exc.public_message()) from exc
            except Exception:
                self._telemetry.tool_calls.add(1, {"tool": tool_name, "outcome": "crash"})
                logger.exception(
                    "tool crashed",
                    extra={
                        "tool": tool_name,
                        "outcome": "crash",
                        "duration_ms": int((time.perf_counter() - started) * 1000),
                    },
                )
                raise
            duration_ms = int((time.perf_counter() - started) * 1000)
            self._telemetry.tool_calls.add(1, {"tool": tool_name, "outcome": "ok"})
            self._telemetry.tool_duration.record(duration_ms, {"tool": tool_name})
            span.set_attribute("aegis.duration_ms", duration_ms)
            logger.info(
                "tool completed",
                extra={"tool": tool_name, "outcome": "ok", "duration_ms": duration_ms},
            )
            return result


class CorrelationMiddleware(ServerMiddleware[Any]):
    """Bind request id, tool name, and principal to context for logs and spans."""

    async def __call__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
        request_token = request_id_var.set(str(ctx.request_id) if ctx.request_id is not None else "-")
        tool_name = "-"
        if ctx.method in {"tools/call", "prompts/get", "resources/read"} and isinstance(ctx.params, dict):
            candidate = ctx.params.get("name") or ctx.params.get("uri")
            if isinstance(candidate, str):
                tool_name = candidate[:128]
        tool_token = tool_var.set(tool_name)
        token = get_access_token()
        principal_name = "local" if token is None else (token.subject or token.client_id)
        principal_token = principal_var.set(principal_name[:128])
        try:
            return await call_next(ctx)
        finally:
            principal_var.reset(principal_token)
            tool_var.reset(tool_token)
            request_id_var.reset(request_token)
