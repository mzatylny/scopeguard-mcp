"""SQLite persistence with a tamper-evident audit hash chain."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import EngagementNotFoundError
from .models import Capability, Engagement, EngagementMode

_GENESIS_HASH = "0" * 64


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _event_hash(previous_hash: str, payload: dict[str, Any]) -> str:
    material = previous_hash + "\n" + _canonical_json(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    ticket TEXT NOT NULL,
                    targets_json TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK(mode IN ('dry-run', 'execute')),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked'))
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    engagement_id TEXT,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_audit_engagement
                ON audit_events(engagement_id, sequence DESC);
                """
            )

    def save_engagement(self, engagement: Engagement) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO engagements (
                    id, title, ticket, targets_json, capabilities_json,
                    mode, created_at, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    engagement.title,
                    engagement.ticket,
                    _canonical_json(list(engagement.targets)),
                    _canonical_json(
                        sorted(capability.value for capability in engagement.capabilities)
                    ),
                    engagement.mode.value,
                    engagement.created_at.isoformat(),
                    engagement.expires_at.isoformat(),
                    engagement.status,
                ),
            )

    def get_engagement(self, engagement_id: str) -> Engagement:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM engagements WHERE id=?", (engagement_id,)
            ).fetchone()
        if row is None:
            raise EngagementNotFoundError(f"engagement not found: {engagement_id}")
        return Engagement(
            id=row["id"],
            title=row["title"],
            ticket=row["ticket"],
            targets=tuple(json.loads(row["targets_json"])),
            capabilities=frozenset(
                Capability(value) for value in json.loads(row["capabilities_json"])
            ),
            mode=EngagementMode(row["mode"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            status=row["status"],
        )

    def revoke_engagement(self, engagement_id: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE engagements SET status='revoked' WHERE id=?", (engagement_id,)
            )
            if cursor.rowcount == 0:
                raise EngagementNotFoundError(f"engagement not found: {engagement_id}")

    def append_audit(
        self,
        *,
        engagement_id: str | None,
        action: str,
        outcome: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        created_at = datetime.now(UTC).isoformat(timespec="milliseconds")
        event_id = uuid.uuid4().hex
        payload = {
            "event_id": event_id,
            "created_at": created_at,
            "engagement_id": engagement_id,
            "action": action,
            "outcome": outcome,
            "details": details,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous_row = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous_row["event_hash"] if previous_row else _GENESIS_HASH
            digest = _event_hash(previous_hash, payload)
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    event_id, created_at, engagement_id, action, outcome,
                    details_json, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    created_at,
                    engagement_id,
                    action,
                    outcome,
                    _canonical_json(details),
                    previous_hash,
                    digest,
                ),
            )
            sequence = int(cursor.lastrowid)
        return {"sequence": sequence, **payload, "previous_hash": previous_hash, "hash": digest}

    def list_audit(self, engagement_id: str, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 1_000))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM audit_events
                WHERE engagement_id=?
                ORDER BY sequence DESC LIMIT ?
                """,
                (engagement_id, bounded_limit),
            ).fetchall()
        return [self._audit_row(row) for row in rows]

    def verify_audit_chain(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence ASC").fetchall()
        expected_previous = _GENESIS_HASH
        for row in rows:
            payload = {
                "event_id": row["event_id"],
                "created_at": row["created_at"],
                "engagement_id": row["engagement_id"],
                "action": row["action"],
                "outcome": row["outcome"],
                "details": json.loads(row["details_json"]),
            }
            expected_hash = _event_hash(expected_previous, payload)
            if row["previous_hash"] != expected_previous or row["event_hash"] != expected_hash:
                return {
                    "valid": False,
                    "events_checked": int(row["sequence"]) - 1,
                    "broken_at_sequence": int(row["sequence"]),
                }
            expected_previous = row["event_hash"]
        return {
            "valid": True,
            "events_checked": len(rows),
            "head_hash": expected_previous,
        }

    @staticmethod
    def _audit_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": int(row["sequence"]),
            "event_id": row["event_id"],
            "created_at": row["created_at"],
            "engagement_id": row["engagement_id"],
            "action": row["action"],
            "outcome": row["outcome"],
            "details": json.loads(row["details_json"]),
            "previous_hash": row["previous_hash"],
            "hash": row["event_hash"],
        }
