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
                "verify_audit_chain",
            }.issubset(names)
            health = await client.call_tool("health", {})
            assert health.structured_content["ok"] is True
            assert health.structured_content["execution_enabled"] is False
    finally:
        server.get_service.cache_clear()
