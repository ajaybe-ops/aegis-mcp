"""Structured logging with correlation IDs and defensive redaction."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from ..config import Settings

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("aegis_request_id", default="-")
principal_var: contextvars.ContextVar[str] = contextvars.ContextVar("aegis_principal", default="anonymous")
tool_var: contextvars.ContextVar[str] = contextvars.ContextVar("aegis_tool", default="-")

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:api[_-]?key|secret|password|token)\s*[:=]\s*)[^\s,;\"']+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]
_SAFE_EXTRA_KEYS = {
    "tool",
    "outcome",
    "duration_ms",
    "provider",
    "status_code",
    "attempt",
    "incident_id",
    "cve_id",
    "scope",
    "cache",
    "cache_hit",
    "retry_after",
    "source",
    "records",
}


def redact(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]" if m.groups() else "[REDACTED]", redacted)
    return redacted


def _trace_ids() -> tuple[str | None, str | None]:
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx.is_valid:
            return None, None
        return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
    except Exception:  # pragma: no cover - telemetry must never break logging
        return None, None


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        trace_id, span_id = _trace_ids()
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
            "request_id": request_id_var.get(),
            "principal": principal_var.get(),
            "tool": tool_var.get(),
            "trace_id": trace_id,
            "span_id": span_id,
        }
        for key in _SAFE_EXTRA_KEYS:
            if hasattr(record, key):
                payload[key] = redact(str(getattr(record, key)))
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, separators=(",", ":"), default=str)


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        trace_id, _ = _trace_ids()
        suffix = f" req={request_id_var.get()} principal={principal_var.get()} tool={tool_var.get()}"
        if trace_id:
            suffix += f" trace={trace_id[:16]}"
        message = record.getMessage()
        return (
            f"{datetime.now(UTC).strftime('%H:%M:%S')} {record.levelname:<7} {record.name}: {redact(message)}{suffix}"
        )


_configured = False


def configure_logging(settings: Settings) -> None:
    """Install one process-wide handler; safe to call from multiple entrypoints."""
    global _configured
    root = logging.getLogger()
    root.setLevel(settings.log_level)
    if _configured:
        return
    for handler in list(root.handlers):
        if getattr(handler, "_aegis_handler", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler._aegis_handler = True  # type: ignore[attr-defined]
    handler.setFormatter(JsonFormatter() if settings.log_format == "json" else ConsoleFormatter())
    root.addHandler(handler)
    # The SDK and uvicorn can be chatty at INFO; keep their access logs but avoid
    # duplicate formatting from their own handlers.
    for name in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True
    _configured = True
