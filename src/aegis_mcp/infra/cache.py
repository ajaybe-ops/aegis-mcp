"""Async TTL + LRU cache with single-flight semantics."""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

import anyio

T = TypeVar("T")


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TTLCache:
    """Bounded cache that collapses concurrent misses for the same key.

    Single-flight matters for expensive upstream calls (KEV catalog, NVD lookups):
    without it, ten concurrent agent calls would fan out into ten identical
    requests and amplify rate-limit pressure.
    """

    def __init__(
        self, *, max_entries: int = 2_048, ttl_seconds: float = 300.0, clock: Callable[[], float] = time.monotonic
    ):
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._ttl = ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._inflight: dict[str, anyio.Event] = {}
        self._lock = anyio.Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._coalesced = 0

    async def get(self, key: str) -> T | None:
        async with self._lock:
            value = self._get_locked(key)
            if value is None:
                self._misses += 1
            else:
                self._hits += 1
            return value

    def _get_locked(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            self._entries.pop(key, None)
            return None
        self._entries.move_to_end(key)
        return entry.value

    async def set(self, key: str, value: Any, *, ttl_seconds: float | None = None) -> None:
        async with self._lock:
            self._set_locked(key, value, ttl_seconds=ttl_seconds)

    def _set_locked(self, key: str, value: Any, *, ttl_seconds: float | None = None) -> None:
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        self._entries[key] = _Entry(value=value, expires_at=self._clock() + ttl)
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
            self._evictions += 1

    async def get_or_create(
        self,
        key: str,
        factory: Callable[[], Awaitable[T]],
        *,
        ttl_seconds: float | None = None,
    ) -> tuple[T, bool]:
        """Return ``(value, cache_hit)``. Concurrent callers share one factory run."""
        waiter: anyio.Event | None = None
        async with self._lock:
            cached = self._get_locked(key)
            if cached is not None:
                self._hits += 1
                return cached, True
            self._misses += 1
            waiter = self._inflight.get(key)
            if waiter is None:
                waiter = anyio.Event()
                self._inflight[key] = waiter
                producer = True
            else:
                self._coalesced += 1
                producer = False

        if not producer:
            await waiter.wait()
            async with self._lock:
                cached = self._get_locked(key)
            if cached is not None:
                self._hits += 1
                return cached, True
            # The producer failed; this caller retries the factory as a new producer.
            return await self.get_or_create(key, factory, ttl_seconds=ttl_seconds)

        try:
            value = await factory()
        except BaseException:
            async with self._lock:
                self._inflight.pop(key, None)
            waiter.set()
            raise
        async with self._lock:
            self._set_locked(key, value, ttl_seconds=ttl_seconds)
            self._inflight.pop(key, None)
        waiter.set()
        return value, False

    async def clear(self) -> None:
        async with self._lock:
            self._entries.clear()

    @property
    def stats(self) -> dict[str, int]:
        return {
            "entries": len(self._entries),
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "coalesced": self._coalesced,
        }
