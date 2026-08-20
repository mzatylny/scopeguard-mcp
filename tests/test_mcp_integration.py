import pytest
from mcp import Client

from scopeguard_mcp import server


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_mcp_v2_discovers_and_calls_structured_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPEGUARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SCOPEGUARD_ALLOWED_ROOTS", str(tmp_path))
    server.get_service.cache_clear()
    try:
        async with Client(server.mcp) as client:
            available = await client.list_tools()
            names = {tool.name for tool in available.tools}
            assert {
                "health",
                "create_dry_run_engagement",
                "scan_repository",
                "probe_http",
                "inspect_tls",
                "probe_tcp_ports",
                "run_posture_assessment",
                "simulate_education_scenario",
                "verify_audit_chain",
            }.issubset(names)
            health = await client.call_tool("health", {})
            assert health.structured_content["ok"] is True
            assert health.structured_content["execution_enabled"] is False
            assert health.structured_content["network_enabled"] is False

            created = await client.call_tool(
                "create_dry_run_engagement",
                {
                    "title": "Offline education test",
                    "ticket": "EDU-TEST",
                    "targets": ["training.invalid"],
                    "capabilities": ["simulate:education"],
                },
            )
            engagement_id = created.structured_content["engagement"]["id"]
            simulation = await client.call_tool(
                "simulate_education_scenario",
                {
                    "engagement_id": engagement_id,
                    "scenario": "web-hardening",
                    "difficulty": "beginner",
                },
            )
            result = simulation.structured_content["simulation"]
            assert result["target"] == "training.invalid"
            assert result["operational"] is False
            assert all(value is False for value in result["guardrails"].values())
    finally:
        server.get_service.cache_clear()
