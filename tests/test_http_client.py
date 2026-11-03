"""Outbound HTTP resilience: allowlists, retries, circuit breaker, and caps."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from aegis_mcp.config import Settings
from aegis_mcp.domain.errors import CircuitOpenError, UpstreamError
from aegis_mcp.infra.telemetry import configure_observability
from aegis_mcp.intel.http import CircuitBreaker, ResilientHttpClient, build_http_client, parse_retry_after

URL = "https://api.test/v1/data"


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _noop_telemetry():
    return configure_observability(
        Settings(_env_file=None, offline=True, otel_enabled=False, auth_mode="local", transport="stdio")
    )


def _client(
    handler,
    *,
    max_retries: int = 2,
    max_response_bytes: int = 1_000,
    failure_threshold: int = 5,
    clock: Clock | None = None,
    sleeps: list[float] | None = None,
) -> ResilientHttpClient:
    transport = httpx.MockTransport(handler)
    async_client = httpx.AsyncClient(transport=transport)
    clock = clock or Clock()
    sleeps = sleeps if sleeps is not None else []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    return ResilientHttpClient(
        client=async_client,
        allowed_hosts={"api.test"},
        max_retries=max_retries,
        base_delay=1.0,
        max_delay=4.0,
        max_response_bytes=max_response_bytes,
        telemetry=_noop_telemetry(),
        failure_threshold=failure_threshold,
        reset_seconds=30.0,
        sleep=sleep,
        random_uniform=lambda low, high: high,
        clock=clock,
    )


async def test_successful_json_object() -> None:
    client = _client(lambda request: httpx.Response(200, json={"ok": True}))
    assert await client.request_json("GET", URL, provider="nvd") == {"ok": True}
    await client.aclose()


async def test_successful_json_array() -> None:
    client = _client(lambda request: httpx.Response(200, json=[1, 2]))
    assert await client.request_json("GET", URL, provider="nvd") == [1, 2]
    await client.aclose()


async def test_empty_response_is_empty_object() -> None:
    client = _client(lambda request: httpx.Response(204))
    assert await client.request_json("GET", URL, provider="nvd") == {}
    await client.aclose()


async def test_allow_404() -> None:
    client = _client(lambda request: httpx.Response(404), max_retries=0)
    assert await client.request_json("GET", URL, provider="nvd", allow_404=True) is None
    await client.aclose()


async def test_404_without_allow_is_non_retryable() -> None:
    client = _client(lambda request: httpx.Response(404), max_retries=0)
    with pytest.raises(UpstreamError) as excinfo:
        await client.request_json("GET", URL, provider="nvd")
    assert excinfo.value.retryable is False
    assert excinfo.value.status_code == 404
    await client.aclose()


async def test_http_is_forbidden() -> None:
    client = _client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(UpstreamError, match="HTTPS"):
        await client.request_json("GET", "http://api.test/v1", provider="nvd")
    await client.aclose()


async def test_host_allowlist() -> None:
    client = _client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(UpstreamError, match="allowlist"):
        await client.request_json("GET", "https://evil.test/v1", provider="nvd")
    await client.aclose()


async def test_credentials_in_url_are_forbidden() -> None:
    client = _client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(UpstreamError, match="credentials"):
        await client.request_json("GET", "https://user:pass@api.test/v1", provider="nvd")
    await client.aclose()


async def test_retry_after_is_honored() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, json={})
        return httpx.Response(200, json={"ok": True})

    client = _client(handler, sleeps=sleeps)
    assert await client.request_json("GET", URL, provider="nvd") == {"ok": True}
    assert calls == 2
    assert sleeps == [0.0]
    await client.aclose()


async def test_exponential_backoff_with_jitter() -> None:
    sleeps: list[float] = []
    client = _client(lambda request: httpx.Response(500, json={}), max_retries=2, sleeps=sleeps)
    with pytest.raises(UpstreamError) as excinfo:
        await client.request_json("GET", URL, provider="nvd")
    assert excinfo.value.retryable is True
    assert sleeps == [1.0, 2.0]
    await client.aclose()


async def test_oversized_response_is_rejected() -> None:
    client = _client(lambda request: httpx.Response(200, content=b"x" * 500), max_response_bytes=100)
    with pytest.raises(UpstreamError, match="exceeded"):
        await client.request_json("GET", URL, provider="nvd")
    await client.aclose()


async def test_invalid_json_is_rejected() -> None:
    client = _client(lambda request: httpx.Response(200, content=b"{not json"))
    with pytest.raises(UpstreamError, match="invalid JSON"):
        await client.request_json("GET", URL, provider="nvd")
    await client.aclose()


async def test_scalar_json_is_rejected() -> None:
    client = _client(lambda request: httpx.Response(200, json="scalar"))
    with pytest.raises(UpstreamError, match="object or array"):
        await client.request_json("GET", URL, provider="nvd")
    await client.aclose()


async def test_transport_failure_is_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("refused", request=request)

    client = _client(handler, max_retries=1)
    with pytest.raises(UpstreamError, match="transport failure"):
        await client.request_json("GET", URL, provider="nvd")
    assert calls == 2
    await client.aclose()


async def test_circuit_breaker_opens_and_recovers() -> None:
    clock = Clock()
    state = {"fail": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if state["fail"]:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"ok": True})

    client = _client(handler, max_retries=0, failure_threshold=2, clock=clock)
    for _ in range(2):
        with pytest.raises(UpstreamError):
            await client.request_json("GET", URL, provider="nvd")
    with pytest.raises(CircuitOpenError) as excinfo:
        await client.request_json("GET", URL, provider="nvd")
    assert excinfo.value.retry_in_seconds == pytest.approx(30.0)
    assert client.breaker_states["api.test"] == "open"

    clock.now += 31
    assert client.breaker_states["api.test"] == "half_open"
    state["fail"] = False
    assert await client.request_json("GET", URL, provider="nvd") == {"ok": True}
    assert client.breaker_states["api.test"] == "closed"
    await client.aclose()


def test_parse_retry_after_seconds_and_date() -> None:
    assert parse_retry_after("3") == 3.0
    assert parse_retry_after("999") == 30.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("garbage") is None
    now = datetime(2026, 1, 1, tzinfo=UTC)
    future = format_datetime(now + timedelta(seconds=10), usegmt=True)
    assert parse_retry_after(future, now=lambda: now.timestamp()) == pytest.approx(10.0, abs=0.1)


def test_circuit_breaker_state_transitions() -> None:
    clock = Clock()
    breaker = CircuitBreaker(name="p", failure_threshold=2, reset_seconds=10, clock=clock)
    assert breaker.state == "closed"
    assert breaker.allow()
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state == "open"
    assert not breaker.allow()
    clock.now += 11
    assert breaker.allow()
    assert breaker.state == "half_open"
    breaker.record_success()
    assert breaker.state == "closed"


async def test_build_http_client_settings() -> None:
    settings = Settings(
        _env_file=None,
        offline=False,
        otel_enabled=False,
        auth_mode="local",
        transport="stdio",
        user_agent="aegis-test/1.0",
    )
    client = build_http_client(settings)
    assert client.headers["user-agent"] == "aegis-test/1.0"
    assert client.follow_redirects is False
    await client.aclose()
