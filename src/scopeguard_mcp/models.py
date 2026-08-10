"""Core immutable domain models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EngagementMode(StrEnum):
    DRY_RUN = "dry-run"
    EXECUTE = "execute"


class Capability(StrEnum):
    PLAN_ASSESSMENT = "plan:assessment"
    ANALYZE_HEADERS = "analyze:headers"
    SCAN_REPOSITORY = "scan:repository"
    READ_AUDIT = "audit:read"


ALL_CAPABILITIES = frozenset(Capability)


@dataclass(frozen=True, slots=True)
class Engagement:
    id: str
    title: str
    ticket: str
    targets: tuple[str, ...]
    capabilities: frozenset[Capability]
    mode: EngagementMode
    created_at: datetime
    expires_at: datetime
    status: str = "active"

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "ticket": self.ticket,
            "targets": list(self.targets),
            "capabilities": sorted(capability.value for capability in self.capabilities),
            "mode": self.mode.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status,
            "expired": self.expired,
        }


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    kind: str
    value: str
    display: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value, "display": self.display}
