"""Application service coordinating policy, analyzers, and audit records."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from . import __version__
from .analyzers import analyze_security_headers, scan_repository
from .config import Settings
from .errors import AnalysisError, AuthorizationError
from .models import Capability, EngagementMode
from .policy import PolicyEngine
from .storage import Store


class ScopeGuardService:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.ensure_state_dir()
        self.store = Store(
            settings.database_path,
            audit_hmac_key=settings.audit_hmac_key,
            audit_key_id=settings.audit_key_id,
        )
        self.policy = PolicyEngine(
            self.store,
            base_dir=settings.project_root,
            max_targets=settings.max_targets,
        )

    def health(self) -> dict[str, Any]:
        audit_chain = self.store.verify_audit_chain()
        execution_ready = (
            not self.settings.execution_enabled
            or not self.settings.require_sealed_audit
            or bool(audit_chain.get("sealed") and audit_chain.get("signature_verified"))
        )
        return {
            "ok": bool(audit_chain["valid"] and execution_ready),
            "name": "scopeguard-mcp",
            "version": __version__,
            "execution_enabled": self.settings.execution_enabled,
            "execution_ready": execution_ready,
            "capabilities": sorted(capability.value for capability in Capability),
            "audit_chain": audit_chain,
        }

    def create_engagement(
        self,
        *,
        title: str,
        ticket: str,
        targets: list[str],
        capabilities: list[str],
        mode: str = EngagementMode.DRY_RUN.value,
        expires_in_minutes: int = 60,
    ) -> dict[str, Any]:
        engagement = self.policy.create_engagement(
            title=title,
            ticket=ticket,
            targets=targets,
            capabilities=capabilities,
            mode=mode,
            expires_in_minutes=expires_in_minutes,
        )
        return {"ok": True, "engagement": engagement.as_dict()}

    def revoke_engagement(self, engagement_id: str, *, operator: bool = True) -> dict[str, Any]:
        engagement = self.store.get_engagement(engagement_id)
        if not operator and engagement.mode is EngagementMode.EXECUTE:
            raise AuthorizationError("execute engagements can be revoked only by the operator CLI")
        self.store.revoke_engagement(engagement_id)
        self.store.append_audit(
            engagement_id=engagement_id,
            action="engagement.revoke",
            outcome="allowed",
            details={},
        )
        return {"ok": True, "engagement_id": engagement_id, "status": "revoked"}

    def revoke_dry_run_engagement(self, engagement_id: str) -> dict[str, Any]:
        """MCP-safe revocation path that cannot alter operator-created execute grants."""
        return self.revoke_engagement(engagement_id, operator=False)

    def check_scope(self, engagement_id: str, target: str) -> dict[str, Any]:
        return {"ok": True, **self.policy.scope_check(engagement_id, target)}

    def plan_assessment(
        self, engagement_id: str, target: str, profile: str = "baseline"
    ) -> dict[str, Any]:
        if profile not in {"baseline", "web", "repository"}:
            raise ValueError("profile must be baseline, web, or repository")
        engagement, normalized = self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.PLAN_ASSESSMENT,
            target=target,
        )
        if profile == "baseline":
            profile = "repository" if normalized.kind == "file" else "web"
        if profile == "repository" and normalized.kind != "file":
            self.store.append_audit(
                engagement_id=engagement_id,
                action="assessment.plan",
                outcome="denied",
                details={"target": normalized.display, "reason_code": "profile_target_mismatch"},
            )
            raise ValueError("repository profile requires a file target")
        if profile == "web" and normalized.kind not in {"url", "domain", "ip"}:
            self.store.append_audit(
                engagement_id=engagement_id,
                action="assessment.plan",
                outcome="denied",
                details={"target": normalized.display, "reason_code": "profile_target_mismatch"},
            )
            raise ValueError("web profile requires a URL, domain, or IP target")
        checks = (
            [
                {"id": "repo.builtin", "kind": "read-only", "available": True},
                {"id": "dependencies.review", "kind": "planned", "available": False},
                {"id": "ci.policy", "kind": "planned", "available": False},
            ]
            if profile == "repository"
            else [
                {"id": "headers.offline", "kind": "offline", "available": True},
                {"id": "tls.inventory", "kind": "planned", "available": False},
                {"id": "dns.inventory", "kind": "planned", "available": False},
            ]
        )
        result = {
            "ok": True,
            "engagement_id": engagement.id,
            "target": normalized.as_dict(),
            "profile": profile,
            "checks": checks,
            "execution_enabled": self.settings.execution_enabled,
        }
        self.store.append_audit(
            engagement_id=engagement_id,
            action="assessment.plan",
            outcome="allowed",
            details={"target": normalized.display, "profile": profile},
        )
        return result

    def analyze_headers(
        self, engagement_id: str, target: str, headers: dict[str, str]
    ) -> dict[str, Any]:
        _, normalized = self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.ANALYZE_HEADERS,
            target=target,
        )
        if normalized.kind != "url":
            self.store.append_audit(
                engagement_id=engagement_id,
                action="headers.analyze",
                outcome="denied",
                details={"target": normalized.display, "reason_code": "target_kind"},
            )
            raise ValueError("header analysis requires an http or https URL target")
        try:
            if len(headers) > self.settings.max_headers:
                raise ValueError(f"at most {self.settings.max_headers} headers are allowed")
            header_bytes = 0
            for name, value in headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ValueError("header names and values must be strings")
                if not name.strip():
                    raise ValueError("header names must not be empty")
                if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                    raise ValueError("header names and values must not contain newlines")
                header_bytes += len(name.encode("utf-8")) + len(value.encode("utf-8"))
            if header_bytes > self.settings.max_header_bytes:
                raise ValueError(
                    f"header input exceeds the {self.settings.max_header_bytes}-byte limit"
                )
        except (AttributeError, TypeError, ValueError) as exc:
            self.store.append_audit(
                engagement_id=engagement_id,
                action="headers.analyze",
                outcome="denied",
                details={"target": normalized.display, "reason_code": "invalid_headers"},
            )
            raise ValueError(str(exc)) from exc
        analysis = analyze_security_headers(normalized.value, headers)
        self.store.append_audit(
            engagement_id=engagement_id,
            action="headers.analyze",
            outcome="allowed",
            details={
                "target": normalized.display,
                "score": analysis["score"],
                "findings": analysis["summary"]["findings"],
            },
        )
        return {"ok": True, "analysis": analysis}

    def scan_repository(self, engagement_id: str, path: str) -> dict[str, Any]:
        engagement, normalized = self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.SCAN_REPOSITORY,
            target=f"file:{path}",
        )
        if normalized.kind != "file":
            raise ValueError("repository scan requires a file target")
        target_path = Path(normalized.value)
        if not any(target_path.is_relative_to(root) for root in self.settings.allowed_roots):
            reason = "target is outside operator-configured allowed roots"
            self.store.append_audit(
                engagement_id=engagement_id,
                action="repository.scan",
                outcome="denied",
                details={"target": normalized.display, "reason": reason},
            )
            raise AuthorizationError(reason)
        if engagement.mode is EngagementMode.DRY_RUN:
            self.store.append_audit(
                engagement_id=engagement_id,
                action="repository.scan",
                outcome="planned",
                details={"target": normalized.display, "reason": "engagement is dry-run"},
            )
            return {
                "ok": True,
                "status": "planned",
                "target": normalized.as_dict(),
                "reason": "engagement is dry-run",
            }
        if not self.settings.execution_enabled:
            reason = "operator has not enabled execution with SCOPEGUARD_EXECUTION_ENABLED=true"
            self.store.append_audit(
                engagement_id=engagement_id,
                action="repository.scan",
                outcome="denied",
                details={"target": normalized.display, "reason": reason},
            )
            raise AuthorizationError(reason)
        if self.settings.require_sealed_audit:
            verification = self.store.verify_audit_chain()
            if not (
                verification["valid"]
                and verification.get("sealed")
                and verification.get("signature_verified")
            ):
                reason = "sealed audit verification is required for execution"
                self.store.append_audit(
                    engagement_id=engagement_id,
                    action="repository.scan",
                    outcome="denied",
                    details={"target": normalized.display, "reason": reason},
                )
                raise AuthorizationError(reason)

        scan_id = self.store.start_scan(
            engagement_id=engagement_id,
            target=normalized.display,
        )
        fingerprint_key = (
            hmac.new(
                self.settings.audit_hmac_key,
                b"scopeguard-secret-fingerprint-v1",
                hashlib.sha256,
            ).digest()
            if self.settings.audit_hmac_key
            else None
        )
        try:
            analysis = scan_repository(
                target_path,
                max_files=self.settings.max_files,
                max_file_bytes=self.settings.max_file_bytes,
                max_total_bytes=self.settings.max_total_bytes,
                max_findings=self.settings.max_findings,
                fingerprint_key=fingerprint_key,
            )
        except (OSError, ValueError) as exc:
            error_code = type(exc).__name__
            self.store.fail_scan(scan_id, error_code=error_code)
            self.store.append_audit(
                engagement_id=engagement_id,
                action="repository.scan",
                outcome="failed",
                details={"target": normalized.display, "error_code": error_code},
            )
            raise AnalysisError("repository analysis could not complete safely") from exc
        evidence = analysis["evidence"]
        self.store.complete_scan(
            scan_id,
            manifest_sha256=evidence["manifest_sha256"],
            ruleset_sha256=evidence["ruleset_sha256"],
            summary=analysis["summary"],
        )
        self.store.append_audit(
            engagement_id=engagement_id,
            action="repository.scan",
            outcome="allowed",
            details={
                "target": normalized.display,
                "scanned_files": analysis["scanned_files"],
                "findings": analysis["summary"]["findings"],
                "truncated": analysis["truncated"],
                "scan_id": scan_id,
                "manifest_sha256": evidence["manifest_sha256"],
                "ruleset_sha256": evidence["ruleset_sha256"],
            },
        )
        return {
            "ok": True,
            "status": "completed",
            "scan_id": scan_id,
            "analysis": analysis,
        }

    def list_audit(self, engagement_id: str, limit: int = 100) -> dict[str, Any]:
        engagement = self.store.get_engagement(engagement_id)
        if Capability.READ_AUDIT not in engagement.capabilities:
            raise AuthorizationError("engagement lacks capability: audit:read")
        return {
            "ok": True,
            "engagement_id": engagement_id,
            "events": self.store.list_audit(engagement_id, limit),
        }

    def verify_audit(self) -> dict[str, Any]:
        return {"ok": True, **self.store.verify_audit_chain()}

    def export_audit_checkpoint(self) -> dict[str, Any]:
        return {"ok": True, "checkpoint": self.store.audit_checkpoint()}

    def list_scan_runs(self, engagement_id: str, limit: int = 100) -> dict[str, Any]:
        engagement = self.store.get_engagement(engagement_id)
        if Capability.READ_AUDIT not in engagement.capabilities:
            raise AuthorizationError("engagement lacks capability: audit:read")
        return {
            "ok": True,
            "engagement_id": engagement_id,
            "runs": self.store.list_scan_runs(engagement_id, limit),
        }
