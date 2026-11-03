"""SQLite persistence for triage reports with idempotency support."""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import anyio

from ..domain.errors import StoreError
from ..domain.models import TriageReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    report_id       TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    generated_at    TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    report_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(incident_id, fingerprint);
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', '1');
"""


class TriageStore:
    """Single-writer async SQLite store.

    SQLite is intentionally used as the zero-dependency default. The store is the
    only stateful component; a Postgres implementation can replace it without
    changing the tools. Writes are serialized by an async lock and WAL mode allows
    concurrent reads in the same process.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = ":memory:" if str(path) == ":memory:" else str(Path(path))
        self._conn: aiosqlite.Connection | None = None
        self._lock = anyio.Lock()
        self._ready = False

    async def initialize(self) -> None:
        if self._ready:
            return
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self._conn = await aiosqlite.connect(self._path)
            self._conn.row_factory = aiosqlite.Row
            if self._path != ":memory:":
                await self._conn.execute("PRAGMA journal_mode=WAL")
                await self._conn.execute("PRAGMA synchronous=NORMAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")
            await self._conn.executescript(_SCHEMA)
            await self._conn.commit()
            self._ready = True
        except Exception as exc:
            raise StoreError("failed to initialize triage store", detail=type(exc).__name__) from exc

    def _connection(self) -> aiosqlite.Connection:
        if self._conn is None or not self._ready:
            raise StoreError("triage store is not initialized")
        return self._conn

    async def save(self, report: TriageReport) -> None:
        conn = self._connection()
        async with self._lock:
            try:
                await conn.execute(
                    """
                    INSERT INTO incidents(incident_id, report_id, fingerprint, generated_at, updated_at, report_json)
                    VALUES (?, ?, ?, ?, datetime('now'), ?)
                    ON CONFLICT(incident_id) DO UPDATE SET
                        report_id=excluded.report_id,
                        fingerprint=excluded.fingerprint,
                        generated_at=excluded.generated_at,
                        updated_at=datetime('now'),
                        report_json=excluded.report_json
                    """,
                    (
                        report.incident_id,
                        report.report_id,
                        report.input_fingerprint,
                        report.generated_at.isoformat(),
                        report.model_dump_json(),
                    ),
                )
                await conn.commit()
            except Exception as exc:
                raise StoreError("failed to persist triage report", detail=type(exc).__name__) from exc

    async def get(self, incident_id: str) -> TriageReport | None:
        conn = self._connection()
        async with (
            self._lock,
            conn.execute("SELECT report_json FROM incidents WHERE incident_id=?", (incident_id,)) as cursor,
        ):
            row = await cursor.fetchone()
        if row is None:
            return None
        try:
            return TriageReport.model_validate_json(row["report_json"])
        except Exception as exc:
            raise StoreError("stored report failed integrity validation", detail=type(exc).__name__) from exc

    async def find(self, incident_id: str, fingerprint: str) -> TriageReport | None:
        conn = self._connection()
        async with (
            self._lock,
            conn.execute(
                "SELECT report_json FROM incidents WHERE incident_id=? AND fingerprint=?",
                (incident_id, fingerprint),
            ) as cursor,
        ):
            row = await cursor.fetchone()
        if row is None:
            return None
        try:
            return TriageReport.model_validate_json(row["report_json"])
        except Exception as exc:
            raise StoreError("stored report failed integrity validation", detail=type(exc).__name__) from exc

    async def count(self) -> int:
        conn = self._connection()
        async with self._lock, conn.execute("SELECT COUNT(*) AS n FROM incidents") as cursor:
            row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def ready(self) -> bool:
        try:
            conn = self._connection()
            async with self._lock, conn.execute("SELECT 1") as cursor:
                await cursor.fetchone()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
            self._ready = False
