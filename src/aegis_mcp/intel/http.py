"""Resilient JSON HTTP client: allowlisted hosts, retries, jitter, circuit breaker."""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import anyio
import httpx

from ..config import Settings
from ..domain.errors import CircuitOpenError, UpstreamError
from ..infra.telemetry import Observability

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


def parse_retry_after(value: str | None, *, now: Callable[[], float] = time.time) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, min(float(value), 30.0))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(value)
        return max(0.0, min(dt.timestamp() - now(), 30.0))
    except (TypeError, ValueError, OverflowError):
        return None


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 5
    reset_seconds: float = 30.0
    clock: Callable[[], float] = field(default=time.monotonic)
    failures: int = 0
    opened_at: float | None = None
    half_open: bool = False

    @property
    def state(self) -> str:
        if self.opened_at is None:
            return "closed"
        if self.clock() - self.opened_at >= self.reset_seconds:
            return "half_open"
        return "open"

    def allow(self) -> bool:
        if self.opened_at is None:
            return True
        if self.clock() - self.opened_at >= self.reset_seconds:
            self.half_open = True
            return True
        return False

    def retry_in(self) -> float:
        if self.opened_at is None:
            return 0.0
        return max(0.0, self.reset_seconds - (self.clock() - self.opened_at))

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None
        self.half_open = False

    def record_failure(self) -> None:
        self.failures += 1
        if self.half_open or self.failures >= self.failure_threshold:
            self.opened_at = self.clock()
            self.half_open = False


class ResilientHttpClient:
    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        allowed_hosts: set[str],
        max_retries: int,
        base_delay: float,
        max_delay: float,
        max_response_bytes: int,
        telemetry: Observability,
        failure_threshold: int = 5,
        reset_seconds: float = 30.0,
        max_concurrency: int = 8,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
        random_uniform: Callable[[float, float], float] = random.uniform,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._allowed_hosts = {host.lower() for host in allowed_hosts}
        self._max_attempts = max_retries + 1
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._max_response_bytes = max_response_bytes
        self._telemetry = telemetry
        self._sleep = sleep
        self._random = random_uniform
        self._clock = clock
        self._breakers: dict[str, CircuitBreaker] = {
            host: CircuitBreaker(
                name=host, failure_threshold=failure_threshold, reset_seconds=reset_seconds, clock=clock
            )
            for host in self._allowed_hosts
        }
        self._semaphore = anyio.Semaphore(max_concurrency)

    def _validate_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise UpstreamError("policy", "only HTTPS upstream URLs are permitted", retryable=False)
        host = (parsed.hostname or "").lower()
        if host not in self._allowed_hosts:
            raise UpstreamError("policy", f"host {host!r} is not on the upstream allowlist", retryable=False)
        if parsed.username or parsed.password:
            raise UpstreamError("policy", "upstream URLs must not contain credentials", retryable=False)
        return url

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        provider: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_404: bool = False,
    ) -> dict[str, Any] | list[Any] | None:
        self._validate_url(url)
        breaker = self._breakers[urlparse(url).hostname or ""]
        if not breaker.allow():
            raise CircuitOpenError(provider, breaker.retry_in())

        last_error: Exception | None = None
        last_status: int | None = None

        for attempt in range(1, self._max_attempts + 1):
            retry_after: float | None = None
            try:
                async with self._semaphore:
                    response = await self._client.request(method, url, params=params, json=json_body, headers=headers)
                last_status = response.status_code

                if response.status_code == 404 and allow_404:
                    breaker.record_success()
                    return None

                if len(response.content) > self._max_response_bytes:
                    breaker.record_success()
                    raise UpstreamError(
                        provider,
                        f"response exceeded {self._max_response_bytes} bytes",
                        retryable=False,
                    )

                if 200 <= response.status_code < 300:
                    if not response.content:
                        breaker.record_success()
                        return {}
                    try:
                        payload = response.json()
                    except ValueError as exc:
                        breaker.record_success()
                        raise UpstreamError(provider, "upstream returned invalid JSON", retryable=False) from exc
                    if not isinstance(payload, dict | list):
                        breaker.record_success()
                        raise UpstreamError(provider, "upstream JSON was not an object or array", retryable=False)
                    breaker.record_success()
                    self._telemetry.upstream_calls.add(1, {"provider": provider, "outcome": "ok"})
                    return payload

                if response.status_code in RETRYABLE_STATUS:
                    retry_after = parse_retry_after(response.headers.get("retry-after"))
                    last_error = UpstreamError(
                        provider,
                        f"upstream returned HTTP {response.status_code}",
                        status_code=response.status_code,
                        retryable=True,
                    )
                    breaker.record_failure()
                else:
                    breaker.record_success()
                    raise UpstreamError(
                        provider,
                        f"upstream rejected request with HTTP {response.status_code}",
                        status_code=response.status_code,
                        retryable=False,
                    )

            except UpstreamError:
                raise
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = UpstreamError(provider, "upstream transport failure", retryable=True)
                breaker.record_failure()
                self._telemetry.add_span_event("upstream.transport_error", {"provider": provider})
                logger.warning(
                    "upstream transport failure",
                    extra={"provider": provider, "attempt": attempt, "outcome": "retry"},
                )
                last_error.__cause__ = exc
            except Exception as exc:  # pragma: no cover - defensive
                breaker.record_success()
                raise UpstreamError(provider, "unexpected upstream client failure", retryable=False) from exc

            if attempt >= self._max_attempts:
                break
            delay = (
                retry_after
                if retry_after is not None
                else min(self._max_delay, self._base_delay * (2 ** (attempt - 1)))
            )
            if retry_after is None:
                delay = self._random(0.0, max(0.0, delay))
            self._telemetry.upstream_retries.add(1, {"provider": provider})
            self._telemetry.add_span_event("upstream.retry", {"provider": provider, "attempt": attempt})
            logger.warning(
                "retrying upstream request",
                extra={"provider": provider, "attempt": attempt, "status_code": last_status},
            )
            await self._sleep(delay)

        self._telemetry.upstream_calls.add(1, {"provider": provider, "outcome": "failed"})
        if last_error is None:  # pragma: no cover
            last_error = UpstreamError(provider, "upstream request failed", retryable=True)
        raise last_error

    @property
    def breaker_states(self) -> dict[str, str]:
        return {name: breaker.state for name, breaker in self._breakers.items()}

    async def aclose(self) -> None:
        await self._client.aclose()


def build_http_client(settings: Settings) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.upstream_timeout_seconds, connect=settings.upstream_connect_timeout_seconds),
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        follow_redirects=False,
        headers={
            "User-Agent": settings.user_agent,
            "Accept": "application/json",
        },
        trust_env=False,
    )
