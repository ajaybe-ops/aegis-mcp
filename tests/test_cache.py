"""TTL, LRU bound, and single-flight behavior."""

from __future__ import annotations

import anyio
import pytest

from aegis_mcp.infra.cache import TTLCache


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def test_set_and_get() -> None:
    cache = TTLCache()
    await cache.set("k", "v", ttl_seconds=10)
    assert await cache.get("k") == "v"


async def test_missing_key_is_none() -> None:
    assert await TTLCache().get("missing") is None


async def test_expiry() -> None:
    clock = Clock()
    cache = TTLCache(clock=clock)
    await cache.set("k", "v", ttl_seconds=5)
    clock.advance(4.9)
    assert await cache.get("k") == "v"
    clock.advance(0.2)
    assert await cache.get("k") is None


async def test_lru_eviction() -> None:
    cache = TTLCache(max_entries=2)
    await cache.set("a", 1)
    await cache.set("b", 2)
    await cache.get("a")  # refresh a
    await cache.set("c", 3)
    assert await cache.get("a") == 1
    assert await cache.get("b") is None
    assert await cache.get("c") == 3
    assert cache.stats["evictions"] == 1


async def test_get_or_create_collapses_concurrent_misses() -> None:
    cache = TTLCache()
    calls = 0
    started = anyio.Event()
    release = anyio.Event()

    async def factory() -> str:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return "value"

    results: list[tuple[str, bool]] = []

    async def worker() -> None:
        results.append(await cache.get_or_create("key", factory))

    async with anyio.create_task_group() as tg:
        tg.start_soon(worker)
        await started.wait()
        tg.start_soon(worker)
        await anyio.sleep(0.01)
        release.set()

    assert calls == 1
    assert sorted(results, key=lambda item: item[1]) == [("value", False), ("value", True)]
    assert cache.stats["coalesced"] == 1


async def test_get_or_create_failure_is_not_cached() -> None:
    cache = TTLCache()
    calls = 0

    async def failing() -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await cache.get_or_create("key", failing)
    assert calls == 1
    assert await cache.get("key") is None

    async def succeeding() -> str:
        return "ok"

    value, hit = await cache.get_or_create("key", succeeding)
    assert value == "ok"
    assert hit is False


async def test_clear_and_stats() -> None:
    cache = TTLCache()
    await cache.set("a", 1)
    await cache.get("a")
    await cache.get("b")
    await cache.clear()
    stats = cache.stats
    assert stats["entries"] == 0
    assert stats["hits"] == 1
    assert stats["misses"] == 1


def test_invalid_max_entries() -> None:
    with pytest.raises(ValueError):
        TTLCache(max_entries=0)
