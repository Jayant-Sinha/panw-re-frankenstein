"""Durable investigation history backed by a small local SQLite database."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any


REPORT_FIELDS = (
    "id", "source_system", "source_type", "observed_at", "ingested_at", "title",
    "category", "origin", "status", "raw_severity", "risk_score", "risk_level",
    "summary", "recommended_action",
)


class HistoryStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS investigation_events (
                    id TEXT PRIMARY KEY,
                    source_system TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    status TEXT NOT NULL,
                    raw_severity INTEGER,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                )
            """)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_history_observed ON investigation_events(observed_at)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_history_source ON investigation_events(source_system)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_history_risk ON investigation_events(risk_level)")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def upsert_event(self, event: dict[str, Any]) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("""
                INSERT INTO investigation_events (
                    id, source_system, source_type, observed_at, ingested_at, title, category,
                    origin, status, raw_severity, risk_score, risk_level, summary,
                    recommended_action, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=CASE WHEN investigation_events.status='mitigated' AND excluded.status!='mitigated' THEN 'mitigated' ELSE excluded.status END,
                    summary=CASE WHEN investigation_events.status='mitigated' AND excluded.status!='mitigated' THEN investigation_events.summary ELSE excluded.summary END,
                    raw_json=excluded.raw_json
            """, (
                event.get("id"), event.get("source_system", "unknown"), event.get("source_type", "unknown"),
                event.get("observed_at", ""), event.get("ingested_at", ""), event.get("title", ""),
                event.get("category", "unknown"), event.get("origin", ""), event.get("status", "active"),
                event.get("raw_severity"), int(event.get("risk_score") or 0), event.get("risk_level", "low"),
                event.get("summary", ""), event.get("recommended_action", ""),
                json.dumps(event.get("raw", {}), ensure_ascii=True),
            ))

    def is_mitigated(self, event_id: str) -> bool:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM investigation_events WHERE id = ?", (event_id,)
            ).fetchone()
        return bool(row and row["status"] == "mitigated")

    def summary(self, days: int = 30) -> dict[str, Any]:
        days = max(1, min(365, int(days)))
        with self._lock, self._connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM investigation_events").fetchone()[0]
            window_total = connection.execute(
                "SELECT COUNT(*) FROM investigation_events WHERE julianday(observed_at) >= julianday('now', ?)",
                (f"-{days} days",),
            ).fetchone()[0]
            by_source = self._counts(connection, "source_system", days)
            by_risk = self._counts(connection, "risk_level", days)
            by_category = self._counts(connection, "category", days)
            by_status = self._counts(connection, "status", days)
            timeline_rows = connection.execute("""
                SELECT substr(observed_at, 1, 13) AS hour, COUNT(*) AS count
                FROM investigation_events
                WHERE julianday(observed_at) >= julianday('now', ?)
                GROUP BY hour ORDER BY hour
            """, (f"-{days} days",)).fetchall()
        return {
            "total_events": total,
            "window_events": window_total,
            "days": days,
            "by_source": by_source,
            "by_risk": by_risk,
            "by_category": by_category,
            "by_status": by_status,
            "timeline": [{"hour": row["hour"], "count": row["count"]} for row in timeline_rows],
        }

    @staticmethod
    def _counts(connection: sqlite3.Connection, column: str, days: int) -> list[dict[str, Any]]:
        allowed = {"source_system", "risk_level", "category", "status"}
        if column not in allowed:
            raise ValueError("Unsupported history aggregation.")
        rows = connection.execute(
            f"SELECT {column} AS label, COUNT(*) AS count FROM investigation_events "
            f"WHERE julianday(observed_at) >= julianday('now', ?) GROUP BY {column} ORDER BY count DESC",
            (f"-{days} days",),
        ).fetchall()
        return [{"label": row["label"], "count": row["count"]} for row in rows]

    def events(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        limit = max(1, min(1000, int(limit)))
        offset = max(0, int(offset))
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM investigation_events ORDER BY observed_at DESC, ingested_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def export_csv(self) -> str:
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=REPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM investigation_events ORDER BY observed_at DESC, ingested_at DESC"
            ).fetchall()
        for row in rows:
            event = self._row_to_event(row)
            writer.writerow({
                key: ("'" + str(value) if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")) else value)
                for key, value in event.items()
            })
        return output.getvalue()

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        event = {key: row[key] for key in REPORT_FIELDS}
        try:
            event["raw"] = json.loads(row["raw_json"])
        except (ValueError, TypeError):
            event["raw"] = {}
        return event
