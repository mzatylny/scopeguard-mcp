from dataclasses import replace

import pytest

from scopeguard_mcp import service as service_module
from scopeguard_mcp.analyzers.network import ResolvedEndpoint
from scopeguard_mcp.config import Settings
from scopeguard_mcp.errors import AuthorizationError, NetworkProbeError
from scopeguard_mcp.service import ScopeGuardService


def _settings(
    tmp_path,
    *,
    execution_enabled=False,
    network_enabled=False,
    allowed_roots=None,
):
    state = tmp_path / "state"
    return Settings(
        project_root=tmp_path,
        state_dir=state,
        database_path=state / "scopeguard.db",
        allowed_roots=tuple(allowed_roots or (tmp_path,)),
        execution_enabled=execution_enabled,
        max_files=100,
        max_file_bytes=100_000,
        network_enabled=network_enabled,
        allowed_hosts=("example.com",),
        allowed_networks=("192.0.2.0/24",),
        max_ports=4,
        network_timeout_seconds=1,
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


def test_network_probe_dry_run_and_dual_operator_gates(tmp_path):
    dry_service = ScopeGuardService(_settings(tmp_path))
    dry = _create(dry_service, "https://example.com/", ["probe:http"])
    assert dry_service.probe_http(dry["id"], "https://example.com/")["status"] == "planned"

    execution_off = ScopeGuardService(_settings(tmp_path, network_enabled=True))
    engagement = _create(execution_off, "https://example.com/", ["probe:http"], mode="execute")
    with pytest.raises(AuthorizationError, match="execution"):
        execution_off.probe_http(engagement["id"], "https://example.com/")

    network_off = ScopeGuardService(_settings(tmp_path, execution_enabled=True))
    engagement = _create(network_off, "https://example.com/", ["probe:http"], mode="execute")
    with pytest.raises(AuthorizationError, match="network probes"):
        network_off.probe_http(engagement["id"], "https://example.com/")


def test_bounded_network_probes_complete_and_audit(tmp_path, monkeypatch):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True, network_enabled=True))
    endpoint = ResolvedEndpoint("example.com", 443, ("192.0.2.10",), "192.0.2.10")
    monkeypatch.setattr(
        service_module, "resolve_allowed_endpoint", lambda *args, **kwargs: endpoint
    )
    monkeypatch.setattr(
        service_module,
        "probe_http_head",
        lambda *args, **kwargs: {"status": 200, "headers": {}},
    )
    monkeypatch.setattr(
        service_module,
        "inspect_tls_endpoint",
        lambda *args, **kwargs: {"protocol": "TLSv1.3", "valid": True},
    )
    monkeypatch.setattr(
        service_module,
        "probe_tcp_ports",
        lambda *args, **kwargs: {"summary": {"requested": 2, "open": 1}},
    )

    http = _create(service, "https://example.com/", ["probe:http", "audit:read"], mode="execute")
    assert service.probe_http(http["id"], "https://example.com/")["status"] == "completed"

    tls = _create(service, "example.com", ["inspect:tls"], mode="execute")
    assert service.inspect_tls(tls["id"], "example.com")["inspection"]["valid"] is True

    tcp = _create(service, "example.com", ["probe:tcp-ports"], mode="execute")
    result = service.probe_tcp_ports(tcp["id"], "example.com", [80, 443])
    assert result["probe"]["summary"]["open"] == 1
    assert service.list_audit(http["id"])["events"]


def test_tcp_probe_validates_target_and_ports_before_resolution(tmp_path, monkeypatch):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True, network_enabled=True))
    monkeypatch.setattr(
        service_module,
        "resolve_allowed_endpoint",
        lambda *args, **kwargs: pytest.fail("invalid input reached endpoint resolution"),
    )
    url = _create(service, "https://example.com/", ["probe:tcp-ports"], mode="execute")
    with pytest.raises(ValueError, match="domain or single IP"):
        service.probe_tcp_ports(url["id"], "https://example.com/", [443])

    domain = _create(service, "example.com", ["probe:tcp-ports"], mode="execute")
    with pytest.raises(ValueError, match="at least one"):
        service.probe_tcp_ports(domain["id"], "example.com", [])
    with pytest.raises(ValueError, match="integers"):
        service.probe_tcp_ports(domain["id"], "example.com", [True])
    with pytest.raises(ValueError, match="limited"):
        service.probe_tcp_ports(domain["id"], "example.com", [1, 2, 3, 4, 5])
    with pytest.raises(ValueError, match="between"):
        service.probe_tcp_ports(domain["id"], "example.com", [0])


def test_network_probe_enforces_operator_hostname_allowlist_and_audits(tmp_path):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True, network_enabled=True))
    engagement = _create(service, "outside.example", ["probe:http", "audit:read"], mode="execute")
    with pytest.raises(AuthorizationError, match="ALLOWED_HOSTS"):
        service.probe_http(engagement["id"], "https://outside.example/")
    events = service.list_audit(engagement["id"])["events"]
    assert any(event["action"] == "http.probe" and event["outcome"] == "denied" for event in events)


def test_tls_probe_validates_port_before_resolution(tmp_path, monkeypatch):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True, network_enabled=True))
    monkeypatch.setattr(
        service_module,
        "resolve_allowed_endpoint",
        lambda *args, **kwargs: pytest.fail("invalid input reached endpoint resolution"),
    )
    engagement = _create(service, "example.com", ["inspect:tls"], mode="execute")
    with pytest.raises(ValueError, match="integer"):
        service.inspect_tls(engagement["id"], "example.com", True)
    with pytest.raises(ValueError, match="between"):
        service.inspect_tls(engagement["id"], "example.com", 0)

    url = _create(service, "https://example.com:8443/", ["inspect:tls"], mode="execute")
    with pytest.raises(ValueError, match="conflicts"):
        service.inspect_tls(url["id"], "https://example.com:8443/", 443)


def _create_workflow_engagement(service, *, mode="dry-run", scheme="https", include_tls=True):
    capabilities = [
        "run:posture-assessment",
        "probe:http",
        "probe:tcp-ports",
        "audit:read",
    ]
    if include_tls:
        capabilities.append("inspect:tls")
    return service.create_engagement(
        title="Guarded posture workflow",
        ticket="SEC-200",
        targets=[f"{scheme}://example.com/", "example.com"],
        capabilities=capabilities,
        mode=mode,
        expires_in_minutes=30,
    )["engagement"]


def test_posture_assessment_dry_run_preflights_fixed_sequence(tmp_path):
    service = ScopeGuardService(_settings(tmp_path))
    engagement = _create_workflow_engagement(service)
    result = service.run_posture_assessment(
        engagement["id"], "https://example.com/", "example.com", [443, 80, 443]
    )
    assert result["status"] == "planned"
    assert result["steps"] == ["probe_tcp_ports", "inspect_tls", "probe_http"]
    assert result["stop_on_error"] is True
    assert result["dynamic_tool_selection"] is False
    assert result["exploitation"] is False


def test_posture_assessment_http_workflow_skips_tls(tmp_path):
    service = ScopeGuardService(_settings(tmp_path))
    engagement = _create_workflow_engagement(service, scheme="http", include_tls=False)
    result = service.run_posture_assessment(
        engagement["id"], "http://example.com/", "example.com", [80]
    )
    assert result["steps"] == ["probe_tcp_ports", "probe_http"]


def test_posture_assessment_executes_only_fixed_preflighted_steps(tmp_path, monkeypatch):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True, network_enabled=True))
    engagement = _create_workflow_engagement(service, mode="execute")
    calls = []

    def tcp(*args):
        calls.append("tcp")
        return {"status": "completed"}

    def tls(*args):
        calls.append("tls")
        return {"status": "completed"}

    def http(*args):
        calls.append("http")
        return {"status": "completed"}

    monkeypatch.setattr(service, "probe_tcp_ports", tcp)
    monkeypatch.setattr(service, "inspect_tls", tls)
    monkeypatch.setattr(service, "probe_http", http)
    result = service.run_posture_assessment(
        engagement["id"], "https://example.com/", "example.com", [80, 443]
    )
    assert calls == ["tcp", "tls", "http"]
    assert result["completed_steps"] == [
        "probe_tcp_ports",
        "inspect_tls",
        "probe_http",
    ]
    assert result["workflow"] == "fixed-sequence"


def test_posture_assessment_stops_on_first_error_and_audits(tmp_path, monkeypatch):
    service = ScopeGuardService(_settings(tmp_path, execution_enabled=True, network_enabled=True))
    engagement = _create_workflow_engagement(service, mode="execute")
    monkeypatch.setattr(service, "probe_tcp_ports", lambda *args: {"status": "completed"})

    def fail_tls(*args):
        raise NetworkProbeError("TLS validation failed")

    monkeypatch.setattr(service, "inspect_tls", fail_tls)
    monkeypatch.setattr(
        service,
        "probe_http",
        lambda *args: pytest.fail("workflow continued after an error"),
    )
    with pytest.raises(NetworkProbeError, match="TLS validation"):
        service.run_posture_assessment(
            engagement["id"], "https://example.com/", "example.com", [443]
        )
    events = service.list_audit(engagement["id"])["events"]
    workflow_error = next(
        event
        for event in events
        if event["action"] == "posture.run" and event["outcome"] == "error"
    )
    assert workflow_error["details"]["completed_steps"] == ["probe_tcp_ports"]


def test_posture_assessment_rejects_mismatched_hosts_and_missing_capability(tmp_path):
    service = ScopeGuardService(_settings(tmp_path))
    mismatch = service.create_engagement(
        title="Mismatched workflow",
        ticket="SEC-201",
        targets=["https://example.com/", "other.example"],
        capabilities=[
            "run:posture-assessment",
            "probe:http",
            "probe:tcp-ports",
            "inspect:tls",
        ],
        mode="dry-run",
        expires_in_minutes=30,
    )["engagement"]
    with pytest.raises(ValueError, match="same host"):
        service.run_posture_assessment(
            mismatch["id"], "https://example.com/", "other.example", [443]
        )

    missing_tls = _create_workflow_engagement(service, include_tls=False)
    with pytest.raises(AuthorizationError, match="inspect:tls"):
        service.run_posture_assessment(
            missing_tls["id"], "https://example.com/", "example.com", [443]
        )


def test_education_simulation_is_dry_run_only_offline_and_audited(tmp_path, monkeypatch):
    service = ScopeGuardService(_settings(tmp_path))
    monkeypatch.setattr(
        service_module,
        "resolve_allowed_endpoint",
        lambda *args, **kwargs: pytest.fail("education simulation attempted network resolution"),
    )
    engagement = _create(
        service,
        "training.invalid",
        ["simulate:education", "audit:read"],
        mode="dry-run",
    )
    result = service.simulate_education(engagement["id"], "repository-secret", "intermediate")
    assert result["status"] == "simulated"
    assert result["simulation"]["target"] == "training.invalid"
    assert result["simulation"]["operational"] is False
    events = service.list_audit(engagement["id"])["events"]
    assert any(
        event["action"] == "education.simulate" and event["outcome"] == "allowed"
        for event in events
    )


def test_education_simulation_rejects_execute_mode_and_real_target_scope(tmp_path):
    service = ScopeGuardService(_settings(tmp_path))
    execute = _create(service, "training.invalid", ["simulate:education"], mode="execute")
    with pytest.raises(AuthorizationError, match="dry-run"):
        service.simulate_education(execute["id"], "web-hardening")

    real_scope = _create(service, "example.com", ["simulate:education"], mode="dry-run")
    with pytest.raises(AuthorizationError, match="outside engagement scope"):
        service.simulate_education(real_scope["id"], "web-hardening")
