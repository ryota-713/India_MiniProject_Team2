from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable
from pathlib import Path

from detection.models import DetectionResult
from detection.serialization import result_from_record, result_to_record


class EventStore:
    def __init__(self, database_path: str | Path = "data/events.sqlite3") -> None:
        self.database_path = str(database_path)
        self._use_uri = self.database_path == ":memory:"
        self._database_dsn = (
            f"file:request-signal-{uuid.uuid4().hex}?mode=memory&cache=shared"
            if self._use_uri
            else self.database_path
        )
        self._keeper = (
            sqlite3.connect(self._database_dsn, uri=True, check_same_thread=False)
            if self._use_uri
            else None
        )
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, record_json TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_dsn,
            timeout=5,
            uri=self._use_uri,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        return connection

    def save_results(self, results: Iterable[DetectionResult]) -> int:
        rows = [
            (
                result.event.event_id,
                result.event.timestamp.isoformat(),
                json.dumps(result_to_record(result), ensure_ascii=False),
            )
            for result in results
        ]
        with self._connect() as connection:
            before = connection.total_changes
            connection.executemany(
                "INSERT OR IGNORE INTO events(event_id, timestamp, record_json) VALUES (?, ?, ?)",
                rows,
            )
            return connection.total_changes - before

    def update_result(self, result: DetectionResult) -> bool:
        record = json.dumps(result_to_record(result), ensure_ascii=False)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE events SET timestamp = ?, record_json = ? WHERE event_id = ?",
                (result.event.timestamp.isoformat(), record, result.event.event_id),
            )
            return cursor.rowcount == 1

    def list_results(self, limit: int = 10_000) -> tuple[DetectionResult, ...]:
        if not 1 <= limit <= 100_000:
            raise ValueError("limit must be between 1 and 100000.")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM events ORDER BY timestamp DESC, event_id LIMIT ?", (limit,)
            ).fetchall()
        return tuple(result_from_record(json.loads(row["record_json"])) for row in rows)

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM events").fetchone()
        return int(row["total"])
