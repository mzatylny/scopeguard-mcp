"""Authorization policy for engagements, capabilities, and target scope."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .errors import AuthorizationError
from .models import ALL_CAPABILITIES, Capability, Engagement, EngagementMode, NormalizedTarget
from .scope import any_scope_matches, normalize_target
from .storage import Store


class PolicyEngine:
    def __init__(self, store: Store, *, base_dir: Path):
        self.store = store
        self.base_dir = base_dir

    def create_engagement(
        self,
        *,
        title: str,
        ticket: str,
        targets: list[str],
        capabilities: list[str],
        mode: str = EngagementMode.DRY_RUN.value,
        expires_in_minutes: int = 60,
    ) -> Engagement:
        clean_title = title.strip()
        clean_ticket = ticket.strip()
        if not clean_title:
            raise ValueError("title must not be empty")
        if not clean_ticket:
            raise ValueError("ticket must not be empty")
        if not targets:
            raise ValueError("at least one target is required")
        if not 1 <= expires_in_minutes <= 24 * 60:
            raise ValueError("expires_in_minutes must be between 1 and 1440")
        normalized_targets = tuple(
            normalize_target(target, base_dir=self.base_dir).display for target in targets
        )
        requested_capabilities = frozenset(Capability(value) for value in capabilities)
        if not requested_capabilities:
            raise ValueError("at least one capability is required")
        if not requested_capabilities.issubset(ALL_CAPABILITIES):
            raise ValueError("unknown capability requested")
        engagement_mode = EngagementMode(mode)
        now = datetime.now(UTC)
        engagement = Engagement(
            id=uuid.uuid4().hex,
            title=clean_title,
            ticket=clean_ticket,
            targets=normalized_targets,
            capabilities=requested_capabilities,
            mode=engagement_mode,
            created_at=now,
            expires_at=now + timedelta(minutes=expires_in_minutes),
        )
        self.store.save_engagement(engagement)
        self.store.append_audit(
            engagement_id=engagement.id,
            action="engagement.create",
            outcome="allowed",
            details={
                "ticket": clean_ticket,
                "targets": list(normalized_targets),
                "capabilities": sorted(value.value for value in requested_capabilities),
                "mode": engagement_mode.value,
            },
        )
        return engagement

    def authorize(
        self,
        *,
        engagement_id: str,
        capability: Capability,
        target: str,
    ) -> tuple[Engagement, NormalizedTarget]:
        engagement = self.store.get_engagement(engagement_id)
        try:
            if engagement.status != "active":
                raise AuthorizationError("engagement is revoked")
            if engagement.expired:
                raise AuthorizationError("engagement has expired")
            if capability not in engagement.capabilities:
                raise AuthorizationError(f"engagement lacks capability: {capability.value}")
            in_scope, normalized = any_scope_matches(
                engagement.targets, target, base_dir=self.base_dir
            )
            if not in_scope:
                raise AuthorizationError(
                    f"target is outside engagement scope: {normalized.display}"
                )
        except AuthorizationError as exc:
            self.store.append_audit(
                engagement_id=engagement_id,
                action="authorization.check",
                outcome="denied",
                details={"capability": capability.value, "target": target, "reason": str(exc)},
            )
            raise
        self.store.append_audit(
            engagement_id=engagement_id,
            action="authorization.check",
            outcome="allowed",
            details={
                "capability": capability.value,
                "target": normalized.display,
            },
        )
        return engagement, normalized

    def scope_check(self, engagement_id: str, target: str) -> dict[str, object]:
        engagement = self.store.get_engagement(engagement_id)
        in_scope, normalized = any_scope_matches(engagement.targets, target, base_dir=self.base_dir)
        self.store.append_audit(
            engagement_id=engagement_id,
            action="scope.check",
            outcome="allowed" if in_scope else "denied",
            details={"target": normalized.display},
        )
        return {"in_scope": in_scope, "target": normalized.as_dict()}
