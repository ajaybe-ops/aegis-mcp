"""SQLite persistence, idempotency lookup, and integrity failures."""

from __future__ import annotations

import json

import pytest

from aegis_mcp.domain.errors import StoreError
from aegis_mcp.infra.store import TriageStore

from .helpers import make_report


async def test_initialize_is_idempotent() -> None:
    store = TriageStore(":memory:")
    await store.initialize()
    await store.initialize()
    assert await store.ready()
    await store.close()
    assert await store.ready() is False


async def test_save_get_and_find() -> None:
    store = TriageStore(":memory:")
    await store.initialize()
    report = make_report()
    await store.save(report)
    loaded = await store.get(report.incident_id)
    assert loaded is not None
    assert loaded.report_id == report.report_id
    assert loaded.input_fingerprint == report.input_fingerprint
    found = await store.find(report.incident_id, report.input_fingerprint)
    assert found is not None
    assert await store.find(report.incident_id, "b" * 64) is None
    assert await store.count() == 1
    await store.close()


async def test_upsert_replaces_report() -> None:
    store = TriageStore(":memory:")
    await store.initialize()
    first = make_report()
    await store.save(first)
    second = make_report(report_id="rpt_ffffffffffffffffffffffff", fingerprint="b" * 64)
    await store.save(second)
    loaded = await store.get(first.incident_id)
    assert loaded is not None
    assert loaded.report_id == second.report_id
    assert loaded.input_fingerprint == "b" * 64
    assert await store.count() == 1
    await store.close()


async def test_missing_report_is_none() -> None:
    store = TriageStore(":memory:")
    await store.initialize()
    assert await store.get("INC-MISSING") is None
    assert await store.find("INC-MISSING", "a" * 64) is None
    await store.close()


async def test_uninitialized_store_fails_closed() -> None:
    store = TriageStore(":memory:")
    with pytest.raises(StoreError, match="not initialized"):
        await store.save(make_report())
    with pytest.raises(StoreError):
        await store.get("INC-1")


async def test_corrupt_row_is_reported_as_store_error() -> None:
    store = TriageStore(":memory:")
    await store.initialize()
    await store.save(make_report())
    assert store._conn is not None
    await store._conn.execute(
        "UPDATE incidents SET report_json=? WHERE incident_id=?",
        (json.dumps({"incident_id": "INC-TEST-1"}), "INC-TEST-1"),
    )
    await store._conn.commit()
    with pytest.raises(StoreError, match="integrity"):
        await store.get("INC-TEST-1")
    await store.close()


async def test_file_backed_store(tmp_path) -> None:
    path = tmp_path / "aegis.db"
    store = TriageStore(path)
    await store.initialize()
    await store.save(make_report())
    await store.close()
    assert path.exists()

    reopened = TriageStore(path)
    await reopened.initialize()
    assert await reopened.count() == 1
    await reopened.close()
