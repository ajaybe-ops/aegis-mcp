"""Token-bucket rate limiting is per principal and per policy."""

from __future__ import annotations

import pytest

from aegis_mcp.domain.errors import RateLimitError
from aegis_mcp.security.limits import LimitPolicy, TokenBucketRateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def _limiter(clock: Clock) -> TokenBucketRateLimiter:
    limiter = TokenBucketRateLimiter(clock=clock)
    limiter.configure("read", LimitPolicy(rate_per_minute=60, burst=2))
    limiter.configure("triage", LimitPolicy(rate_per_minute=1, burst=1))
    return limiter


async def test_burst_then_reject() -> None:
    clock = Clock()
    limiter = _limiter(clock)
    await limiter.acquire("alice", "read")
    await limiter.acquire("alice", "read")
    with pytest.raises(RateLimitError) as excinfo:
        await limiter.acquire("alice", "read")
    assert excinfo.value.retry_after_seconds == pytest.approx(1.0)
    assert limiter.stats["rejections"] == 1


async def test_refill_over_time() -> None:
    clock = Clock()
    limiter = _limiter(clock)
    await limiter.acquire("alice", "read")
    await limiter.acquire("alice", "read")
    clock.now += 1.0
    await limiter.acquire("alice", "read")


async def test_principals_are_isolated() -> None:
    clock = Clock()
    limiter = _limiter(clock)
    await limiter.acquire("alice", "read")
    await limiter.acquire("alice", "read")
    await limiter.acquire("bob", "read")


async def test_policies_are_isolated() -> None:
    clock = Clock()
    limiter = _limiter(clock)
    await limiter.acquire("alice", "triage")
    with pytest.raises(RateLimitError):
        await limiter.acquire("alice", "triage")
    await limiter.acquire("alice", "read")


async def test_unknown_policy() -> None:
    limiter = _limiter(Clock())
    with pytest.raises(KeyError):
        await limiter.acquire("alice", "unknown")


async def test_remaining_reflects_bucket() -> None:
    clock = Clock()
    limiter = _limiter(clock)
    assert await limiter.remaining("alice", "read") == 2.0
    await limiter.acquire("alice", "read")
    assert await limiter.remaining("alice", "read") == 1.0


async def test_bucket_eviction_under_pressure() -> None:
    clock = Clock()
    limiter = TokenBucketRateLimiter(clock=clock)
    limiter.configure("read", LimitPolicy(rate_per_minute=60, burst=1))
    limiter._max_buckets = 2
    for index in range(4):
        clock.now += 1
        await limiter.acquire(f"user-{index}", "read")
    assert limiter.stats["buckets"] <= 2
