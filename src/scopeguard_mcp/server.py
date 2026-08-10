"""MCP v2 server exposing ScopeGuard's policy-first defensive tools."""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from typing import Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .config import Settings
from .errors import ScopeGuardError
from .models import EngagementMode
from .service import ScopeGuardService

mcp = MCPServer(
    name="scopeguard-mcp",
    title="ScopeGuard MCP",
    description="Policy-first defensive security operations with explicit target scope.",
    version=__version__,
    instructions=(
        "Use only for systems and repositories the operator is authorized to assess. "
        "Every target operation requires an unexpired engagement and explicit capability. "
        "MCP clients can create dry-run engagements only; execute engagements must be "
        "created by an operator through the local CLI. No arbitrary shell or network "
        "execution is exposed."
    ),
)


@lru_cache(maxsize=1)
def get_service() -> ScopeGuardService:
    return ScopeGuardService(Settings.from_env())


def _safe_call(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return operation()
    except (ScopeGuardError, ValueError) as exc:
        return {
            "ok": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }


@mcp.tool(
    title="ScopeGuard health",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def health() -> dict[str, Any]:
    """Return server safety settings, capabilities, and audit-chain health."""
    return _safe_call(get_service().health)


@mcp.tool(
    title="Create dry-run engagement",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
    ),
)
def create_dry_run_engagement(
    title: str,
    ticket: str,
    targets: list[str],
    capabilities: list[str],
    expires_in_minutes: int = 60,
) -> dict[str, Any]:
    """Create a non-executing assessment scope; execute mode is operator-CLI only."""
    return _safe_call(
        lambda: get_service().create_engagement(
            title=title,
            ticket=ticket,
            targets=targets,
            capabilities=capabilities,
            mode=EngagementMode.DRY_RUN.value,
            expires_in_minutes=expires_in_minutes,
        )
    )


@mcp.tool(
    title="Revoke engagement",
    annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
    ),
)
def revoke_engagement(engagement_id: str) -> dict[str, Any]:
    """Immediately revoke an engagement and prevent further target operations."""
    return _safe_call(lambda: get_service().revoke_engagement(engagement_id))


@mcp.tool(
    title="Check target scope",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def check_scope(engagement_id: str, target: str) -> dict[str, Any]:
    """Normalize a target and report whether it is inside the engagement scope."""
    return _safe_call(lambda: get_service().check_scope(engagement_id, target))


@mcp.tool(
    title="Plan defensive assessment",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def plan_assessment(engagement_id: str, target: str, profile: str = "baseline") -> dict[str, Any]:
    """Create a bounded web or repository assessment plan without running network tools."""
    return _safe_call(lambda: get_service().plan_assessment(engagement_id, target, profile))


@mcp.tool(
    title="Analyze HTTP security headers",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def analyze_headers(engagement_id: str, target: str, headers: dict[str, str]) -> dict[str, Any]:
    """Analyze caller-supplied response headers offline; no HTTP request is performed."""
    return _safe_call(lambda: get_service().analyze_headers(engagement_id, target, headers))


@mcp.tool(
    title="Scan authorized local repository",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def scan_repository(engagement_id: str, path: str) -> dict[str, Any]:
    """Run built-in read-only Python and secret checks under operator-allowed roots."""
    return _safe_call(lambda: get_service().scan_repository(engagement_id, path))


@mcp.tool(
    title="Read engagement audit events",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def list_audit_events(engagement_id: str, limit: int = 100) -> dict[str, Any]:
    """Return recent audit events when the engagement includes audit:read."""
    return _safe_call(lambda: get_service().list_audit(engagement_id, limit))


@mcp.tool(
    title="Verify audit chain",
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    ),
)
def verify_audit_chain() -> dict[str, Any]:
    """Verify every persisted event against the tamper-evident hash chain."""
    return _safe_call(get_service().verify_audit)


def main() -> None:
    """Run the safest default transport: local stdio only."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
