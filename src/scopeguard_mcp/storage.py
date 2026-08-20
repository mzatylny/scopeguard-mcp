"""SQLite persistence with a tamper-evident audit hash chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, EngagementNotFoundError
from .models import Capability, Engagement, EngagementMode

_GENESIS_HASH = "0" * 64


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _event_hash(previous_hash: str, payload: dict[str, Any]) -> str:
    material = previous_hash + "\n" + _canonical_json(payload)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _checkpoint_signature(key: bytes, *, event_count: int, head_hash: str, key_id: str) -> str:
    material = _canonical_json(
        {"event_count": event_count, "head_hash": head_hash, "key_id": key_id}
    )
    return hmac.new(key, material.encode("utf-8"), hashlib.sha256).hexdigest()


class Store:
    def __init__(
        self,
        database_path: Path,
        *,
        audit_hmac_key: bytes | None = None,
        audit_key_id: str = "unsealed",
    ):
        self.database_path = database_path
        self.audit_hmac_key = audit_hmac_key
        self.audit_key_id = audit_key_id if audit_hmac_key else "unsealed"
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass
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

                CREATE TABLE IF NOT EXISTS audit_checkpoint (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    event_count INTEGER NOT NULL,
                    head_hash TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    signature TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    manifest_sha256 TEXT,
                    ruleset_sha256 TEXT,
                    summary_json TEXT,
                    error_code TEXT,
                    FOREIGN KEY(engagement_id) REFERENCES engagements(id)
                );

                CREATE INDEX IF NOT EXISTS idx_scan_runs_engagement
                ON scan_runs(engagement_id, started_at DESC);
                """
            )
            self._ensure_audit_checkpoint(connection)

    def _ensure_audit_checkpoint(self, connection: sqlite3.Connection) -> None:
        row = connection.execute("SELECT * FROM audit_checkpoint WHERE singleton=1").fetchone()
        if row is not None:
            if self.audit_hmac_key and row["signature"] is None:
                migrated_signature = _checkpoint_signature(
                    self.audit_hmac_key,
                    event_count=int(row["event_count"]),
                    head_hash=row["head_hash"],
                    key_id=self.audit_key_id,
                )
                connection.execute(
                    "UPDATE audit_checkpoint SET key_id=?, signature=? WHERE singleton=1",
                    (self.audit_key_id, migrated_signature),
                )
            return
        last = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        event_count = int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
        head_hash = last["event_hash"] if last else _GENESIS_HASH
        initial_signature = (
            _checkpoint_signature(
                self.audit_hmac_key,
                event_count=event_count,
                head_hash=head_hash,
                key_id=self.audit_key_id,
            )
            if self.audit_hmac_key
            else None
        )
        connection.execute(
            """
            INSERT INTO audit_checkpoint (
                singleton, event_count, head_hash, key_id, signature
            ) VALUES (1, ?, ?, ?, ?)
            """,
            (event_count, head_hash, self.audit_key_id, initial_signature),
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
            event_count = int(connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
            checkpoint = connection.execute(
                "SELECT * FROM audit_checkpoint WHERE singleton=1"
            ).fetchone()
            if checkpoint is None:
                raise ConfigurationError("audit checkpoint is missing")
            if (
                int(checkpoint["event_count"]) != event_count
                or checkpoint["head_hash"] != previous_hash
            ):
                raise ConfigurationError("audit checkpoint does not match persisted events")
            if checkpoint["signature"] is not None:
                if self.audit_hmac_key is None:
                    raise ConfigurationError(
                        "sealed audit history requires SCOPEGUARD_AUDIT_HMAC_KEY"
                    )
                if checkpoint["key_id"] != self.audit_key_id:
                    raise ConfigurationError("configured audit key ID does not match checkpoint")
                expected_signature = _checkpoint_signature(
                    self.audit_hmac_key,
                    event_count=event_count,
                    head_hash=previous_hash,
                    key_id=self.audit_key_id,
                )
                if not hmac.compare_digest(checkpoint["signature"], expected_signature):
                    raise ConfigurationError("audit checkpoint signature is invalid")
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
            if cursor.lastrowid is None:
                raise ConfigurationError("audit event insert did not return a sequence")
            sequence = int(cursor.lastrowid)
            next_count = event_count + 1
            next_signature = (
                _checkpoint_signature(
                    self.audit_hmac_key,
                    event_count=next_count,
                    head_hash=digest,
                    key_id=self.audit_key_id,
                )
                if self.audit_hmac_key
                else None
            )
            connection.execute(
                """
                UPDATE audit_checkpoint
                SET event_count=?, head_hash=?, key_id=?, signature=?
                WHERE singleton=1
                """,
                (next_count, digest, self.audit_key_id, next_signature),
            )
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
            checkpoint = connection.execute(
                "SELECT * FROM audit_checkpoint WHERE singleton=1"
            ).fetchone()
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
                    "reason": "event_chain_mismatch",
                    "sealed": bool(checkpoint and checkpoint["signature"]),
                }
            expected_previous = row["event_hash"]
        if checkpoint is None:
            return {
                "valid": False,
                "events_checked": len(rows),
                "head_hash": expected_previous,
                "reason": "checkpoint_missing",
                "sealed": False,
            }
        if (
            int(checkpoint["event_count"]) != len(rows)
            or checkpoint["head_hash"] != expected_previous
        ):
            return {
                "valid": False,
                "events_checked": len(rows),
                "head_hash": expected_previous,
                "reason": "checkpoint_mismatch",
                "sealed": bool(checkpoint["signature"]),
            }
        sealed = checkpoint["signature"] is not None
        signature_verified: bool | None = None
        if sealed and self.audit_hmac_key is not None:
            if checkpoint["key_id"] != self.audit_key_id:
                return {
                    "valid": False,
                    "events_checked": len(rows),
                    "head_hash": expected_previous,
                    "reason": "checkpoint_key_mismatch",
                    "sealed": True,
                    "signature_verified": False,
                }
            expected_signature = _checkpoint_signature(
                self.audit_hmac_key,
                event_count=len(rows),
                head_hash=expected_previous,
                key_id=self.audit_key_id,
            )
            signature_verified = hmac.compare_digest(checkpoint["signature"], expected_signature)
            if not signature_verified:
                return {
                    "valid": False,
                    "events_checked": len(rows),
                    "head_hash": expected_previous,
                    "reason": "checkpoint_signature_invalid",
                    "sealed": True,
                    "signature_verified": False,
                }
        return {
            "valid": True,
            "events_checked": len(rows),
            "head_hash": expected_previous,
            "sealed": sealed,
            "key_id": checkpoint["key_id"],
            "signature_verified": signature_verified,
        }

    def audit_checkpoint(self) -> dict[str, Any]:
        """Return the portable audit head without exposing signing key material."""
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM audit_checkpoint WHERE singleton=1").fetchone()
        if row is None:
            raise ConfigurationError("audit checkpoint is missing")
        return {
            "event_count": int(row["event_count"]),
            "head_hash": row["head_hash"],
            "key_id": row["key_id"],
            "signature": row["signature"],
            "sealed": row["signature"] is not None,
        }

    def start_scan(self, *, engagement_id: str, target: str) -> str:
        scan_id = uuid.uuid4().hex
        started_at = datetime.now(UTC).isoformat(timespec="milliseconds")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_runs (
                    id, engagement_id, target, status, started_at
                ) VALUES (?, ?, ?, 'running', ?)
                """,
                (scan_id, engagement_id, target, started_at),
            )
        return scan_id

    def complete_scan(
        self,
        scan_id: str,
        *,
        manifest_sha256: str,
        ruleset_sha256: str,
        summary: dict[str, Any],
    ) -> None:
        completed_at = datetime.now(UTC).isoformat(timespec="milliseconds")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_runs
                SET status='completed', completed_at=?, manifest_sha256=?,
                    ruleset_sha256=?, summary_json=?, error_code=NULL
                WHERE id=? AND status='running'
                """,
                (
                    completed_at,
                    manifest_sha256,
                    ruleset_sha256,
                    _canonical_json(summary),
                    scan_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ConfigurationError("invalid scan state transition")

    def fail_scan(self, scan_id: str, *, error_code: str) -> None:
        completed_at = datetime.now(UTC).isoformat(timespec="milliseconds")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_runs
                SET status='failed', completed_at=?, error_code=?
                WHERE id=? AND status='running'
                """,
                (completed_at, error_code, scan_id),
            )
            if cursor.rowcount != 1:
                raise ConfigurationError("invalid scan state transition")

    def list_scan_runs(self, engagement_id: str, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 1_000))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM scan_runs
                WHERE engagement_id=?
                ORDER BY started_at DESC LIMIT ?
                """,
                (engagement_id, bounded_limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "engagement_id": row["engagement_id"],
                "target": row["target"],
                "status": row["status"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "manifest_sha256": row["manifest_sha256"],
                "ruleset_sha256": row["ruleset_sha256"],
                "summary": json.loads(row["summary_json"]) if row["summary_json"] else None,
                "error_code": row["error_code"],
            }
            for row in rows
        ]

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
