from types import SimpleNamespace

from scopeguard_mcp import server
from scopeguard_mcp.errors import AuthorizationError


class FakeService:
    def health(self):
        return {"ok": True, "fake": True}

    def create_engagement(self, **kwargs):
        return kwargs

    def revoke_engagement(self, engagement_id):
        return {"id": engagement_id, "status": "revoked"}

    def check_scope(self, engagement_id, target):
        return {"id": engagement_id, "target": target}

    def plan_assessment(self, engagement_id, target, profile):
        return {"id": engagement_id, "target": target, "profile": profile}

    def analyze_headers(self, engagement_id, target, headers):
        return {"id": engagement_id, "target": target, "headers": headers}

    def scan_repository(self, engagement_id, path):
        return {"id": engagement_id, "path": path}

    def probe_http(self, engagement_id, target):
        return {"id": engagement_id, "target": target, "kind": "http"}

    def inspect_tls(self, engagement_id, target, port):
        return {"id": engagement_id, "target": target, "port": port, "kind": "tls"}

    def probe_tcp_ports(self, engagement_id, target, ports):
        return {"id": engagement_id, "target": target, "ports": ports, "kind": "tcp"}

    def run_posture_assessment(self, engagement_id, url_target, host_target, ports):
        return {
            "id": engagement_id,
            "url_target": url_target,
            "host_target": host_target,
            "ports": ports,
            "kind": "workflow",
        }

    def list_audit(self, engagement_id, limit):
        return {"id": engagement_id, "limit": limit}

    def verify_audit(self):
        return {"ok": True, "valid": True}


def test_server_tools_delegate_and_force_dry_run(monkeypatch):
    fake = FakeService()
    monkeypatch.setattr(server, "get_service", lambda: fake)
    assert server.health()["fake"] is True
    created = server.create_dry_run_engagement(
        "Title", "SEC-1", ["example.com"], ["plan:assessment"], 30
    )
    assert created["mode"] == "dry-run"
    assert server.revoke_engagement("eng")["status"] == "revoked"
    assert server.check_scope("eng", "example.com")["target"] == "example.com"
    assert server.plan_assessment("eng", "example.com", "web")["profile"] == "web"
    assert server.analyze_headers("eng", "https://example.com", {"x": "y"})["headers"]
    assert server.scan_repository("eng", ".")["path"] == "."
    assert server.probe_http("eng", "https://example.com")["kind"] == "http"
    assert server.inspect_tls("eng", "example.com", 8443)["port"] == 8443
    assert server.probe_tcp_ports("eng", "example.com", [80, 443])["ports"] == [80, 443]
    assert (
        server.run_posture_assessment("eng", "https://example.com", "example.com", [80, 443])[
            "kind"
        ]
        == "workflow"
    )
    assert server.list_audit_events("eng", 5)["limit"] == 5
    assert server.verify_audit_chain()["valid"] is True


def test_server_returns_structured_expected_errors():
    result = server._safe_call(lambda: (_ for _ in ()).throw(AuthorizationError("denied")))
    assert result == {
        "ok": False,
        "error": {"type": "AuthorizationError", "message": "denied"},
    }


def test_server_main_uses_stdio(monkeypatch):
    called = SimpleNamespace(transport=None)
    monkeypatch.setattr(
        server.mcp, "run", lambda *, transport: setattr(called, "transport", transport)
    )
    server.main()
    assert called.transport == "stdio"
