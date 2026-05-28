from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Iterable

from .models import AlertEvent


class AlertStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    proto TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    response_action TEXT NOT NULL DEFAULT 'logged'
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)")

    def add_alert(self, event: AlertEvent, response_action: str = "logged") -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    timestamp, src_ip, dest_ip, proto, signature,
                    severity, category, event_type, raw_json, response_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    event.src_ip,
                    event.dest_ip,
                    event.proto,
                    event.signature,
                    event.severity,
                    event.category,
                    event.event_type,
                    json.dumps(event.raw, sort_keys=True),
                    response_action,
                ),
            )

    def recent_alerts(self, limit: int = 50) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT timestamp, src_ip, dest_ip, proto, signature, severity,
                       category, event_type, response_action
                FROM alerts
                ORDER BY datetime(timestamp) DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [dict(row) for row in rows]

    def alerts_in_window(self, src_ip: str, window_seconds: int) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM alerts
                WHERE src_ip = ?
                  AND timestamp >= datetime('now', ?)
                """,
                (src_ip, f"-{window_seconds} seconds"),
            ).fetchone()

        return int(row["count"] if row else 0)

    def summary(self) -> dict[str, object]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT timestamp, src_ip, severity, response_action FROM alerts ORDER BY datetime(timestamp) ASC"
            ).fetchall()

        total = len(rows)
        by_source = Counter(row["src_ip"] for row in rows)
        by_action = Counter(row["response_action"] for row in rows)
        by_hour = Counter()
        for row in rows:
            hour_key = row["timestamp"][:13]
            by_hour[hour_key] += 1

        return {
            "total_alerts": total,
            "top_sources": by_source.most_common(10),
            "response_actions": dict(by_action),
            "hourly_counts": dict(sorted(by_hour.items())),
        }

    def insert_many(self, events: Iterable[AlertEvent]) -> None:
        for event in events:
            self.add_alert(event)
