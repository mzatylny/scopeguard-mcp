import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from scopeguard_mcp.errors import ConfigurationError, EngagementNotFoundError
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


def test_signed_checkpoint_detects_tail_deletion_and_blocks_append(tmp_path):
    database_path = tmp_path / "scopeguard.db"
    key = b"k" * 32
    store = Store(database_path, audit_hmac_key=key, audit_key_id="test-key")
    store.save_engagement(_engagement())
    store.append_audit(engagement_id="eng-1", action="one", outcome="allowed", details={})
    store.append_audit(engagement_id="eng-1", action="two", outcome="allowed", details={})
    verification = store.verify_audit_chain()
    assert verification["valid"] is True
    assert verification["sealed"] is True
    assert verification["signature_verified"] is True

    with sqlite3.connect(database_path) as connection:
        connection.execute("DELETE FROM audit_events WHERE sequence=2")
    verification = store.verify_audit_chain()
    assert verification["valid"] is False
    assert verification["reason"] == "checkpoint_mismatch"
    with pytest.raises(ConfigurationError, match="checkpoint"):
        store.append_audit(engagement_id="eng-1", action="three", outcome="allowed", details={})


def test_scan_run_state_is_durable_and_transition_checked(tmp_path):
    store = Store(tmp_path / "scopeguard.db")
    store.save_engagement(_engagement())
    scan_id = store.start_scan(engagement_id="eng-1", target="file:/repo")
    store.complete_scan(
        scan_id,
        manifest_sha256="a" * 64,
        ruleset_sha256="b" * 64,
        summary={"findings": 1},
    )
    runs = store.list_scan_runs("eng-1")
    assert runs[0]["status"] == "completed"
    assert runs[0]["manifest_sha256"] == "a" * 64
    with pytest.raises(ConfigurationError, match="transition"):
        store.fail_scan(scan_id, error_code="late")
