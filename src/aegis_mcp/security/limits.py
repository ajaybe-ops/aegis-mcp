"""Token-bucket rate limiting keyed by principal and operation class."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

import anyio

from ..domain.errors import RateLimitError


@dataclass
class _Bucket:
    tokens: float
    updated_at: float
    last_seen: float


@dataclass(frozen=True)
class LimitPolicy:
    rate_per_minute: int
    burst: int

    @property
    def rate_per_second(self) -> float:
        return self.rate_per_minute / 60.0


@dataclass
class TokenBucketRateLimiter:
    """Process-local limiter.

    This is deliberately dependency-free and per-replica. A horizontally scaled
    deployment must replace the store with Redis (see docs/OPERATIONS.md); the
    interface is intentionally small so that swap is contained.
    """

    clock: Callable[[], float] = field(default=time.monotonic)
    _policies: dict[str, LimitPolicy] = field(default_factory=dict)
    _buckets: dict[tuple[str, str], _Bucket] = field(default_factory=dict)
    _lock: anyio.Lock = field(default_factory=anyio.Lock)
    _rejections: int = 0
    _max_buckets: int = 50_000

    def configure(self, name: str, policy: LimitPolicy) -> None:
        self._policies[name] = policy

    async def acquire(self, principal: str, policy_name: str) -> None:
        policy = self._policies.get(policy_name)
        if policy is None:
            raise KeyError(f"unknown rate-limit policy: {policy_name}")
        key = (policy_name, principal)
        now = self.clock()
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=float(policy.burst), updated_at=now, last_seen=now)
                self._buckets[key] = bucket
                self._evict_if_needed(now)
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(float(policy.burst), bucket.tokens + elapsed * policy.rate_per_second)
            bucket.updated_at = now
            bucket.last_seen = now
            if bucket.tokens < 1.0:
                self._rejections += 1
                wait = (1.0 - bucket.tokens) / policy.rate_per_second
                raise RateLimitError(f"{policy_name} principal {principal}", max(wait, 0.1))
            bucket.tokens -= 1.0

    def _evict_if_needed(self, now: float) -> None:
        if len(self._buckets) <= self._max_buckets:
            return
        cutoff = now - 600
        stale = [key for key, bucket in self._buckets.items() if bucket.last_seen < cutoff]
        for key in stale[: self._max_buckets // 10]:
            self._buckets.pop(key, None)
        # Under a burst of unique principals there may be nothing stale yet.
        # Evict the least-recently-seen buckets so memory stays bounded rather
        # than letting an attacker grow the map without limit.
        while len(self._buckets) > self._max_buckets:
            oldest = min(self._buckets, key=lambda key: self._buckets[key].last_seen)
            self._buckets.pop(oldest, None)

    async def remaining(self, principal: str, policy_name: str) -> float:
        policy = self._policies[policy_name]
        async with self._lock:
            bucket = self._buckets.get((policy_name, principal))
            if bucket is None:
                return float(policy.burst)
            elapsed = max(0.0, self.clock() - bucket.updated_at)
            return min(float(policy.burst), bucket.tokens + elapsed * policy.rate_per_second)

    @property
    def stats(self) -> dict[str, int]:
        return {"buckets": len(self._buckets), "rejections": self._rejections}
