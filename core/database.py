"""SQLite-backed history of every operation the toolkit performs.

A single append-only ``runs`` table records each :class:`OperationResult` with
its tool, action, status, timing and a JSON blob of the details. This gives the
``history`` command an audit trail and lets deployments look up the last known
-good version for rollback. The database is created on first use and pruned by
retention age.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from core.base import OperationResult
from utils.exceptions import DatabaseError
from utils.security import redact, redact_data

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tool        TEXT NOT NULL,
    action      TEXT NOT NULL,
    status      TEXT NOT NULL,
    message     TEXT,
    duration_ms INTEGER DEFAULT 0,
    data        TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_tool ON runs(tool);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);
"""


class HistoryDB:
    """Thin, safe wrapper around the ``runs`` history table."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.path))
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Could not open history database: {exc}") from exc

    def __enter__(self) -> "HistoryDB":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def record(self, result: OperationResult) -> int:
        """Persist an :class:`OperationResult`; return its row id."""
        try:
            cur = self._conn.execute(
                "INSERT INTO runs (tool, action, status, message, duration_ms, data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    result.tool,
                    result.action,
                    result.status.value,
                    redact(result.message),
                    result.duration_ms,
                    json.dumps(redact_data(result.data), default=str),
                    result.started_at,
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to record run: {exc}") from exc

    def recent(self, *, tool: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent runs, newest first, optionally filtered."""
        query = "SELECT * FROM runs"
        params: list[Any] = []
        if tool:
            query += " WHERE tool = ?"
            params.append(tool)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, int(limit)))
        try:
            rows = self._conn.execute(query, params).fetchall()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to query history: {exc}") from exc
        return [self._row_to_dict(r) for r in rows]

    def summary(self) -> dict[str, Any]:
        """Aggregate counts of runs by tool and by status."""
        try:
            by_status = {
                r["status"]: r["n"]
                for r in self._conn.execute(
                    "SELECT status, COUNT(*) AS n FROM runs GROUP BY status"
                )
            }
            by_tool = {
                r["tool"]: r["n"]
                for r in self._conn.execute(
                    "SELECT tool, COUNT(*) AS n FROM runs GROUP BY tool ORDER BY n DESC"
                )
            }
            total = self._conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to summarise history: {exc}") from exc
        return {"total": total, "by_status": by_status, "by_tool": by_tool}

    def last_success(self, tool: str, action: str) -> dict[str, Any] | None:
        """Return the most recent successful run of *tool*/*action* (or None)."""
        try:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE tool = ? AND action = ? AND status = 'success' "
                "ORDER BY id DESC LIMIT 1",
                (tool, action),
            ).fetchone()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to query history: {exc}") from exc
        return self._row_to_dict(row) if row else None

    def prune(self, retention_days: int) -> int:
        """Delete rows older than *retention_days*; return the number removed."""
        if retention_days <= 0:
            return 0
        try:
            cur = self._conn.execute(
                "DELETE FROM runs WHERE created_at < datetime('now', ?)",
                (f"-{int(retention_days)} days",),
            )
            self._conn.commit()
            return cur.rowcount
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to prune history: {exc}") from exc

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:  # pragma: no cover
            pass

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        record = dict(row)
        try:
            record["data"] = json.loads(record.get("data") or "{}")
        except (TypeError, json.JSONDecodeError):  # pragma: no cover
            record["data"] = {}
        return record
