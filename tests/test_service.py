from dataclasses import replace

import pytest

from scopeguard_mcp.config import Settings
from scopeguard_mcp.errors import AuthorizationError
from scopeguard_mcp.service import ScopeGuardService


def _settings(tmp_path, *, execution_enabled=False, allowed_roots=None):
    state = tmp_path / "state"
    return Settings(
        project_root=tmp_path,
        state_dir=state,
        database_path=state / "scopeguard.db",
        allowed_roots=tuple(allowed_roots or (tmp_path,)),
        execution_enabled=execution_enabled,
        max_files=100,
        max_file_bytes=100_000,
    )


def _create(service, target, capabilities, mode="dry-run"):
    return service.create_engagement(
        title="Authorized review",
        ticket="SEC-100",
        targets=[target],
        capabilities=capabilities,
        mode=mode,
        expires_in_minutes=60,
    )["engagement"]


def test_health_scope_plan_and_audit(tmp_path):
    service = ScopeGuardService(_settings(tmp_path))
    engagement = _create(
        service,
        "https://example.com/app",
        ["plan:assessment", "analyze:headers", "audit:read"],
    )
    engagement_id = engagement["id"]
    assert service.health()["audit_chain"]["valid"] is True
    assert service.check_scope(engagement_id, "https://example.com/app/page")["in_scope"]
    plan = service.plan_assessment(
        engagement_id, "https://example.com/app/page", profile="baseline"
    )
    assert plan["profile"] == "web"
    analysis = service.analyze_headers(engagement_id, "https://example.com/app/page", {})
    assert analysis["analysis"]["summary"]["findings"] > 0
    assert service.list_audit(engagement_id, limit=20)["events"]


def test_repository_scan_dry_run_then_execute(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "risky.py").write_text("eval(data)\n", encoding="utf-8")

    dry_service = ScopeGuardService(_settings(tmp_path))
    dry = _create(dry_service, f"file:{repo}", ["scan:repository"], mode="dry-run")
    planned = dry_service.scan_repository(dry["id"], str(repo))
    assert planned["status"] == "planned"

    disabled_service = ScopeGuardService(_settings(tmp_path))
    disabled = _create(disabled_service, f"file:{repo}", ["scan:repository"], mode="execute")
    with pytest.raises(AuthorizationError, match="not enabled"):
        disabled_service.scan_repository(disabled["id"], str(repo))

    enabled_settings = replace(_settings(tmp_path), execution_enabled=True)
    enabled_service = ScopeGuardService(enabled_settings)
    enabled = _create(enabled_service, f"file:{repo}", ["scan:repository"], mode="execute")
    completed = enabled_service.scan_repository(enabled["id"], str(repo))
    assert completed["status"] == "completed"
    assert completed["analysis"]["summary"]["high"] == 1


def test_repository_scan_enforces_operator_roots(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    service = ScopeGuardService(
        _settings(tmp_path, execution_enabled=True, allowed_roots=(allowed,))
    )
    engagement = _create(service, f"file:{tmp_path}", ["scan:repository"], mode="execute")
    with pytest.raises(AuthorizationError, match="allowed roots"):
        service.scan_repository(engagement["id"], str(outside))


@pytest.mark.parametrize(
    "profile,target,error",
    [
        ("unknown", "example.com", "profile"),
        ("repository", "example.com", "file target"),
        ("web", "file:.", "URL, domain, or IP"),
    ],
)
def test_assessment_plan_validates_profile(tmp_path, profile, target, error):
    service = ScopeGuardService(_settings(tmp_path))
    engagement = _create(service, target, ["plan:assessment"], mode="dry-run")
    with pytest.raises(ValueError, match=error):
        service.plan_assessment(engagement["id"], target, profile)


def test_audit_access_requires_capability_and_revoke_blocks_operations(tmp_path):
    service = ScopeGuardService(_settings(tmp_path))
    engagement = _create(service, "example.com", ["plan:assessment"])
    with pytest.raises(AuthorizationError, match="audit:read"):
        service.list_audit(engagement["id"])
    assert service.revoke_engagement(engagement["id"])["status"] == "revoked"
    with pytest.raises(AuthorizationError, match="revoked"):
        service.plan_assessment(engagement["id"], "example.com")


def test_mcp_revocation_cannot_revoke_operator_execute_engagement(tmp_path):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True))
    engagement = _create(
        service,
        f"file:{tmp_path}",
        ["scan:repository"],
        mode="execute",
    )
    with pytest.raises(AuthorizationError, match="operator CLI"):
        service.revoke_dry_run_engagement(engagement["id"])
    assert service.store.get_engagement(engagement["id"]).status == "active"


def test_header_input_limits_and_newlines_are_rejected(tmp_path):
    settings = replace(_settings(tmp_path), max_headers=1, max_header_bytes=12)
    service = ScopeGuardService(settings)
    engagement = _create(
        service,
        "https://example.com",
        ["analyze:headers"],
    )
    with pytest.raises(ValueError, match="at most 1"):
        service.analyze_headers(
            engagement["id"],
            "https://example.com",
            {"a": "1", "b": "2"},
        )
    with pytest.raises(ValueError, match="newlines"):
        service.analyze_headers(
            engagement["id"],
            "https://example.com",
            {"x-test": "safe\r\ninjected: yes"},
        )


def test_execute_scan_requires_and_records_signed_evidence(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text("print('safe')\n", encoding="utf-8")

    unsealed_settings = replace(
        _settings(tmp_path, execution_enabled=True),
        require_sealed_audit=True,
    )
    unsealed_service = ScopeGuardService(unsealed_settings)
    unsealed = _create(
        unsealed_service,
        f"file:{repo}",
        ["scan:repository"],
        mode="execute",
    )
    assert unsealed_service.health()["execution_ready"] is False
    with pytest.raises(AuthorizationError, match="sealed audit"):
        unsealed_service.scan_repository(unsealed["id"], str(repo))

    sealed_state = tmp_path / "sealed-state"
    sealed_settings = replace(
        _settings(tmp_path, execution_enabled=True),
        state_dir=sealed_state,
        database_path=sealed_state / "scopeguard.db",
        require_sealed_audit=True,
        audit_hmac_key=b"s" * 32,
        audit_key_id="test-key",
    )
    sealed_service = ScopeGuardService(sealed_settings)
    sealed = _create(
        sealed_service,
        f"file:{repo}",
        ["scan:repository", "audit:read"],
        mode="execute",
    )
    completed = sealed_service.scan_repository(sealed["id"], str(repo))
    assert completed["status"] == "completed"
    assert completed["scan_id"]
    assert sealed_service.health()["execution_ready"] is True
    runs = sealed_service.list_scan_runs(sealed["id"])["runs"]
    assert runs[0]["id"] == completed["scan_id"]
    assert runs[0]["manifest_sha256"] == completed["analysis"]["evidence"]["manifest_sha256"]
