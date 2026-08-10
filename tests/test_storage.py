import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from scopeguard_mcp.errors import EngagementNotFoundError
from scopeguard_mcp.models import Capability, Engagement, EngagementMode
from scopeguard_mcp.storage import Store


def _engagement(identifier="eng-1"):
    now = datetime.now(UTC)
    return Engagement(
        id=identifier,
        title="Authorized test",
        ticket="SEC-123",
        targets=("example.com",),
        capabilities=frozenset({Capability.PLAN_ASSESSMENT, Capability.READ_AUDIT}),
        mode=EngagementMode.DRY_RUN,
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )


def test_engagement_round_trip_and_revoke(tmp_path):
    store = Store(tmp_path / "scopeguard.db")
    expected = _engagement()
    store.save_engagement(expected)
    assert store.get_engagement(expected.id) == expected
    store.revoke_engagement(expected.id)
    assert store.get_engagement(expected.id).status == "revoked"


def test_unknown_engagement_operations_fail(tmp_path):
    store = Store(tmp_path / "scopeguard.db")
    with pytest.raises(EngagementNotFoundError):
        store.get_engagement("missing")
    with pytest.raises(EngagementNotFoundError):
        store.revoke_engagement("missing")


def test_audit_chain_round_trip_and_tamper_detection(tmp_path):
    database_path = tmp_path / "scopeguard.db"
    store = Store(database_path)
    store.save_engagement(_engagement())
    first = store.append_audit(
        engagement_id="eng-1", action="one", outcome="allowed", details={"safe": True}
    )
    second = store.append_audit(
        engagement_id="eng-1", action="two", outcome="denied", details={"reason": "scope"}
    )
    assert second["previous_hash"] == first["hash"]
    events = store.list_audit("eng-1")
    assert [event["action"] for event in events] == ["two", "one"]
    assert store.verify_audit_chain()["valid"] is True

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE audit_events SET details_json=? WHERE sequence=1", ('{"safe":false}',)
        )
    verification = store.verify_audit_chain()
    assert verification["valid"] is False
    assert verification["broken_at_sequence"] == 1


def test_duplicate_engagement_is_rejected(tmp_path):
    store = Store(tmp_path / "scopeguard.db")
    store.save_engagement(_engagement())
    with pytest.raises(sqlite3.IntegrityError):
        store.save_engagement(_engagement())
