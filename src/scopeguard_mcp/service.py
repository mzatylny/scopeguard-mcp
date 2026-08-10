"""Application service coordinating policy, analyzers, and audit records."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .analyzers import (
    analyze_security_headers,
    inspect_tls_endpoint,
    probe_http_head,
    probe_tcp_ports,
    resolve_allowed_endpoint,
    scan_repository,
)
from .config import Settings
from .errors import AuthorizationError, NetworkProbeError, ScopeGuardError
from .models import Capability, Engagement, EngagementMode, NormalizedTarget
from .policy import PolicyEngine
from .storage import Store


class ScopeGuardService:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.ensure_state_dir()
        self.store = Store(settings.database_path)
        self.policy = PolicyEngine(self.store, base_dir=settings.project_root)

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "name": "scopeguard-mcp",
            "version": __version__,
            "execution_enabled": self.settings.execution_enabled,
            "network_enabled": self.settings.network_enabled,
            "network_policy": {
                "allowed_host_patterns": len(self.settings.allowed_hosts),
                "allowed_networks": len(self.settings.allowed_networks),
                "max_ports": self.settings.max_ports,
                "timeout_seconds": self.settings.network_timeout_seconds,
            },
            "capabilities": sorted(capability.value for capability in Capability),
            "audit_chain": self.store.verify_audit_chain(),
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

    def revoke_engagement(self, engagement_id: str) -> dict[str, Any]:
        self.store.revoke_engagement(engagement_id)
        self.store.append_audit(
            engagement_id=engagement_id,
            action="engagement.revoke",
            outcome="allowed",
            details={},
        )
        return {"ok": True, "engagement_id": engagement_id, "status": "revoked"}

    def check_scope(self, engagement_id: str, target: str) -> dict[str, Any]:
        return {"ok": True, **self.policy.scope_check(engagement_id, target)}

    def plan_assessment(
        self, engagement_id: str, target: str, profile: str = "baseline"
    ) -> dict[str, Any]:
        engagement, normalized = self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.PLAN_ASSESSMENT,
            target=target,
        )
        if profile not in {"baseline", "web", "repository"}:
            raise ValueError("profile must be baseline, web, or repository")
        if profile == "baseline":
            profile = "repository" if normalized.kind == "file" else "web"
        if profile == "repository" and normalized.kind != "file":
            raise ValueError("repository profile requires a file target")
        if profile == "web" and normalized.kind not in {"url", "domain", "ip"}:
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
                {
                    "id": "http.head",
                    "kind": "bounded-network",
                    "available": self._network_available,
                },
                {
                    "id": "tls.handshake",
                    "kind": "bounded-network",
                    "available": self._network_available,
                },
                {
                    "id": "tcp.connect",
                    "kind": "bounded-network",
                    "available": self._network_available,
                },
                {
                    "id": "workflow.posture",
                    "kind": "fixed-sequence",
                    "available": self._network_available,
                },
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
            raise ValueError("header analysis requires an http or https URL target")
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

    @property
    def _network_available(self) -> bool:
        return (
            self.settings.execution_enabled
            and self.settings.network_enabled
            and bool(self.settings.allowed_networks)
        )

    def _authorize_network(
        self,
        *,
        engagement_id: str,
        capability: Capability,
        target: str,
        action: str,
    ) -> tuple[Engagement, NormalizedTarget] | dict[str, Any]:
        engagement, normalized = self.policy.authorize(
            engagement_id=engagement_id,
            capability=capability,
            target=target,
        )
        if engagement.mode is EngagementMode.DRY_RUN:
            self.store.append_audit(
                engagement_id=engagement_id,
                action=action,
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
            reason = "operator has not enabled execution"
        elif not self.settings.network_enabled:
            reason = "operator has not enabled bounded network probes"
        else:
            return engagement, normalized
        self.store.append_audit(
            engagement_id=engagement_id,
            action=action,
            outcome="denied",
            details={"target": normalized.display, "reason": reason},
        )
        raise AuthorizationError(reason)

    def _resolve_endpoint(self, engagement_id: str, action: str, host: str, port: int, target: str):
        try:
            return resolve_allowed_endpoint(
                host,
                port,
                allowed_hosts=self.settings.allowed_hosts,
                allowed_networks=self.settings.allowed_networks,
            )
        except (AuthorizationError, NetworkProbeError) as exc:
            self.store.append_audit(
                engagement_id=engagement_id,
                action=action,
                outcome="denied" if isinstance(exc, AuthorizationError) else "error",
                details={"target": target, "reason": str(exc)},
            )
            raise

    def probe_http(self, engagement_id: str, target: str) -> dict[str, Any]:
        action = "http.probe"
        authorized = self._authorize_network(
            engagement_id=engagement_id,
            capability=Capability.PROBE_HTTP,
            target=target,
            action=action,
        )
        if isinstance(authorized, dict):
            return authorized
        _, normalized = authorized
        if normalized.kind != "url":
            raise ValueError("HTTP probe requires an http or https URL target")
        parsed = urlsplit(normalized.value)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        endpoint = self._resolve_endpoint(
            engagement_id, action, parsed.hostname or "", port, normalized.display
        )
        try:
            result = probe_http_head(
                normalized.value,
                endpoint,
                timeout=self.settings.network_timeout_seconds,
            )
        except NetworkProbeError as exc:
            self.store.append_audit(
                engagement_id=engagement_id,
                action=action,
                outcome="error",
                details={"target": normalized.display, "reason": str(exc)},
            )
            raise
        result["security_headers"] = analyze_security_headers(normalized.value, result["headers"])
        self.store.append_audit(
            engagement_id=engagement_id,
            action=action,
            outcome="allowed",
            details={
                "target": normalized.display,
                "address": endpoint.selected_address,
                "status": result["status"],
            },
        )
        return {"ok": True, "status": "completed", "probe": result}

    def inspect_tls(
        self, engagement_id: str, target: str, port: int | None = None
    ) -> dict[str, Any]:
        action = "tls.inspect"
        authorized = self._authorize_network(
            engagement_id=engagement_id,
            capability=Capability.INSPECT_TLS,
            target=target,
            action=action,
        )
        if isinstance(authorized, dict):
            return authorized
        if port is not None and (not isinstance(port, int) or isinstance(port, bool)):
            raise ValueError("TLS port must be an integer")
        if port is not None and not 1 <= port <= 65_535:
            raise ValueError("TLS port must be between 1 and 65535")
        _, normalized = authorized
        if normalized.kind == "url":
            parsed = urlsplit(normalized.value)
            host = parsed.hostname or ""
            if parsed.port is not None and port is not None and parsed.port != port:
                raise ValueError("TLS port conflicts with the explicit URL port")
            selected_port = parsed.port or port or 443
        elif normalized.kind in {"domain", "ip"}:
            host = normalized.value
            selected_port = port or 443
        else:
            raise ValueError("TLS inspection requires a URL, domain, or single IP target")
        endpoint = self._resolve_endpoint(
            engagement_id, action, host, selected_port, normalized.display
        )
        try:
            result = inspect_tls_endpoint(endpoint, timeout=self.settings.network_timeout_seconds)
        except NetworkProbeError as exc:
            self.store.append_audit(
                engagement_id=engagement_id,
                action=action,
                outcome="error",
                details={"target": normalized.display, "reason": str(exc)},
            )
            raise
        self.store.append_audit(
            engagement_id=engagement_id,
            action=action,
            outcome="allowed",
            details={
                "target": normalized.display,
                "address": endpoint.selected_address,
                "protocol": result["protocol"],
            },
        )
        return {"ok": True, "status": "completed", "inspection": result}

    def probe_tcp_ports(self, engagement_id: str, target: str, ports: list[int]) -> dict[str, Any]:
        action = "tcp.probe"
        authorized = self._authorize_network(
            engagement_id=engagement_id,
            capability=Capability.PROBE_TCP_PORTS,
            target=target,
            action=action,
        )
        if isinstance(authorized, dict):
            return authorized
        _, normalized = authorized
        if normalized.kind not in {"domain", "ip"}:
            raise ValueError("TCP probe requires a domain or single IP target")
        unique_ports = self._validate_ports(ports)
        endpoint = self._resolve_endpoint(
            engagement_id, action, normalized.value, unique_ports[0], normalized.display
        )
        result = probe_tcp_ports(
            endpoint,
            unique_ports,
            timeout=self.settings.network_timeout_seconds,
            max_ports=self.settings.max_ports,
        )
        self.store.append_audit(
            engagement_id=engagement_id,
            action=action,
            outcome="allowed",
            details={
                "target": normalized.display,
                "address": endpoint.selected_address,
                "requested_ports": unique_ports,
                "open_ports": result["summary"]["open"],
            },
        )
        return {"ok": True, "status": "completed", "probe": result}

    def _validate_ports(self, ports: list[int]) -> list[int]:
        if not ports:
            raise ValueError("at least one TCP port is required")
        if any(not isinstance(port, int) or isinstance(port, bool) for port in ports):
            raise ValueError("TCP ports must be integers")
        unique_ports = sorted(set(ports))
        if len(unique_ports) > self.settings.max_ports:
            raise ValueError(f"TCP probe is limited to {self.settings.max_ports} unique ports")
        if any(not 1 <= port <= 65_535 for port in unique_ports):
            raise ValueError("TCP ports must be between 1 and 65535")
        return unique_ports

    def run_posture_assessment(
        self,
        engagement_id: str,
        url_target: str,
        host_target: str,
        ports: list[int],
    ) -> dict[str, Any]:
        """Run only the fixed bounded probe sequence after a complete preflight."""
        action = "posture.run"
        engagement, normalized_url = self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.RUN_POSTURE_ASSESSMENT,
            target=url_target,
        )
        if normalized_url.kind != "url":
            raise ValueError("posture assessment requires an http or https URL target")
        self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.PROBE_HTTP,
            target=url_target,
        )
        _, normalized_host = self.policy.authorize(
            engagement_id=engagement_id,
            capability=Capability.PROBE_TCP_PORTS,
            target=host_target,
        )
        if normalized_host.kind not in {"domain", "ip"}:
            raise ValueError("posture assessment host must be a domain or single IP")
        parsed = urlsplit(normalized_url.value)
        if parsed.hostname != normalized_host.value:
            raise ValueError("URL and host targets must identify the same host")
        include_tls = parsed.scheme == "https"
        if include_tls:
            self.policy.authorize(
                engagement_id=engagement_id,
                capability=Capability.INSPECT_TLS,
                target=url_target,
            )
        unique_ports = self._validate_ports(ports)
        steps = ["probe_tcp_ports"]
        if include_tls:
            steps.append("inspect_tls")
        steps.append("probe_http")
        if engagement.mode is EngagementMode.DRY_RUN:
            self.store.append_audit(
                engagement_id=engagement_id,
                action=action,
                outcome="planned",
                details={
                    "url_target": normalized_url.display,
                    "host_target": normalized_host.display,
                    "ports": unique_ports,
                    "steps": steps,
                },
            )
            return {
                "ok": True,
                "status": "planned",
                "workflow": "fixed-sequence",
                "steps": steps,
                "stop_on_error": True,
                "dynamic_tool_selection": False,
                "exploitation": False,
            }
        self._authorize_network(
            engagement_id=engagement_id,
            capability=Capability.RUN_POSTURE_ASSESSMENT,
            target=url_target,
            action=action,
        )
        completed_steps: list[str] = []
        results: dict[str, Any] = {}
        try:
            results["tcp"] = self.probe_tcp_ports(
                engagement_id, normalized_host.display, unique_ports
            )
            completed_steps.append("probe_tcp_ports")
            if include_tls:
                results["tls"] = self.inspect_tls(engagement_id, normalized_url.display)
                completed_steps.append("inspect_tls")
            results["http"] = self.probe_http(engagement_id, normalized_url.display)
            completed_steps.append("probe_http")
        except (ScopeGuardError, ValueError) as exc:
            self.store.append_audit(
                engagement_id=engagement_id,
                action=action,
                outcome="error",
                details={
                    "target": normalized_url.display,
                    "completed_steps": completed_steps,
                    "reason": str(exc),
                },
            )
            raise
        self.store.append_audit(
            engagement_id=engagement_id,
            action=action,
            outcome="allowed",
            details={
                "target": normalized_url.display,
                "completed_steps": completed_steps,
            },
        )
        return {
            "ok": True,
            "status": "completed",
            "workflow": "fixed-sequence",
            "completed_steps": completed_steps,
            "stop_on_error": True,
            "dynamic_tool_selection": False,
            "exploitation": False,
            "results": results,
        }

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
        analysis = scan_repository(
            target_path,
            max_files=self.settings.max_files,
            max_file_bytes=self.settings.max_file_bytes,
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
            },
        )
        return {"ok": True, "status": "completed", "analysis": analysis}

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
