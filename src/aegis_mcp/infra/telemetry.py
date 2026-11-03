"""OpenTelemetry tracing and metrics with a safe no-op fallback."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.trace import Span, Status, StatusCode

from ..config import Settings
from ..version import __version__

logger = logging.getLogger(__name__)

_http_instrumented = False


def _otlp_endpoint(base: str, suffix: str) -> str:
    base = base.rstrip("/")
    if base.endswith(suffix):
        return base
    return base + suffix


class Observability:
    """Thin facade so application code never depends on an exporter being configured."""

    def __init__(
        self,
        *,
        tracer: trace.Tracer,
        meter: metrics.Meter,
        span_provider: TracerProvider | None = None,
        meter_provider: MeterProvider | None = None,
    ) -> None:
        self.tracer = tracer
        self.meter = meter
        self._span_provider = span_provider
        self._meter_provider = meter_provider
        self.tool_calls = meter.create_counter("aegis.tool.calls", description="Tool invocations by outcome")
        self.tool_duration = meter.create_histogram("aegis.tool.duration", unit="ms", description="Tool latency")
        self.upstream_calls = meter.create_counter("aegis.upstream.calls", description="Outbound provider requests")
        self.upstream_retries = meter.create_counter("aegis.upstream.retries", description="Retried outbound requests")
        self.cache_requests = meter.create_counter("aegis.cache.requests", description="Cache lookups")
        self.rate_limit_rejections = meter.create_counter("aegis.ratelimit.rejections", description="Rejected calls")
        self.auth_denials = meter.create_counter("aegis.auth.denials", description="Authorization denials")
        self.triage_findings = meter.create_histogram("aegis.triage.findings", description="Findings per triage")
        self.triage_duration = meter.create_histogram("aegis.triage.duration", unit="ms", description="Triage latency")

    @contextlib.contextmanager
    def span(self, name: str, attributes: dict[str, Any] | None = None) -> Iterator[Span]:
        clean_attributes = {
            key: value for key, value in (attributes or {}).items() if isinstance(value, str | int | float | bool)
        }
        with self.tracer.start_as_current_span(name, attributes=clean_attributes, record_exception=False) as span:
            try:
                yield span
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
                raise

    def add_span_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        span = trace.get_current_span()
        if span.is_recording():
            span.add_event(name, attributes=attributes or {})

    def shutdown(self) -> None:
        if self._span_provider is not None:
            self._span_provider.shutdown()
        if self._meter_provider is not None:
            self._meter_provider.shutdown()


def configure_observability(settings: Settings) -> Observability:
    if not settings.otel_enabled:
        return Observability(
            tracer=trace.NoOpTracerProvider().get_tracer("aegis-mcp"),
            meter=metrics.NoOpMeterProvider().get_meter("aegis-mcp"),
        )

    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.version": __version__,
            "service.namespace": "aegis",
            "deployment.environment.name": settings.environment,
        }
    )
    span_provider = TracerProvider(resource=resource)
    if settings.otel_console_export:
        span_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    if settings.otel_endpoint:
        span_exporter = OTLPSpanExporter(endpoint=_otlp_endpoint(settings.otel_endpoint, "/v1/traces"), timeout=5)
        span_provider.add_span_processor(BatchSpanProcessor(span_exporter))

    meter_provider: MeterProvider | None = None
    if settings.otel_endpoint:
        metric_exporter = OTLPMetricExporter(endpoint=_otlp_endpoint(settings.otel_endpoint, "/v1/metrics"), timeout=5)
        reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=15_000)
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])

    try:
        trace.set_tracer_provider(span_provider)
    except Exception:  # pragma: no cover - another provider already installed
        logger.warning("global tracer provider already set; Aegis spans use its own provider")
    if meter_provider is not None:
        try:
            metrics.set_meter_provider(meter_provider)
        except Exception:  # pragma: no cover
            logger.warning("global meter provider already set")

    global _http_instrumented
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        if not _http_instrumented:
            HTTPXClientInstrumentor().instrument(tracer_provider=span_provider)
            _http_instrumented = True
    except Exception:  # pragma: no cover - instrumentation is optional
        logger.warning("httpx OpenTelemetry instrumentation unavailable")

    return Observability(
        tracer=span_provider.get_tracer("aegis-mcp"),
        meter=(meter_provider or metrics.NoOpMeterProvider()).get_meter("aegis-mcp"),
        span_provider=span_provider,
        meter_provider=meter_provider,
    )


def instrument_asgi(app: Any) -> Any:
    """Best-effort Starlette instrumentation; returns the app unchanged on failure."""
    try:
        from opentelemetry.instrumentation.starlette import StarletteInstrumentor

        if not getattr(app, "_is_instrumented_by_opentelemetry", False):
            StarletteInstrumentor.instrument_app(app)
    except Exception:  # pragma: no cover
        logger.warning("Starlette instrumentation unavailable")
    return app
