from datetime import UTC, datetime, timedelta

import pytest

from scopeguard_mcp.errors import AuthorizationError
from scopeguard_mcp.models import Capability, Engagement, EngagementMode
from scopeguard_mcp.policy import PolicyEngine
from scopeguard_mcp.storage import Store


def _policy(tmp_path):
    return PolicyEngine(Store(tmp_path / "scopeguard.db"), base_dir=tmp_path)


def test_create_and_authorize_engagement(tmp_path):
    policy = _policy(tmp_path)
    engagement = policy.create_engagement(
        title=" Web review ",
        ticket=" SEC-42 ",
        targets=["*.example.com"],
        capabilities=["plan:assessment"],
        expires_in_minutes=30,
    )
    assert engagement.title == "Web review"
    assert engagement.ticket == "SEC-42"
    authorized, target = policy.authorize(
        engagement_id=engagement.id,
        capability=Capability.PLAN_ASSESSMENT,
        target="https://api.example.com/path",
    )
    assert authorized.id == engagement.id
    assert target.value == "https://api.example.com/path"


def test_authorization_denies_missing_capability_and_out_of_scope(tmp_path):
    policy = _policy(tmp_path)
    engagement = policy.create_engagement(
        title="Review",
        ticket="SEC-42",
        targets=["example.com"],
        capabilities=["plan:assessment"],
    )
    with pytest.raises(AuthorizationError, match="lacks capability"):
        policy.authorize(
            engagement_id=engagement.id,
            capability=Capability.ANALYZE_HEADERS,
            target="https://example.com",
        )
    with pytest.raises(AuthorizationError, match="outside"):
        policy.authorize(
            engagement_id=engagement.id,
            capability=Capability.PLAN_ASSESSMENT,
            target="https://other.example",
        )
    outcomes = [event["outcome"] for event in policy.store.list_audit(engagement.id)]
    assert outcomes.count("denied") == 2


def test_authorization_denies_expired_and_revoked_engagements(tmp_path):
    policy = _policy(tmp_path)
    now = datetime.now(UTC)
    expired = Engagement(
        id="expired",
        title="Expired",
        ticket="SEC-1",
        targets=("example.com",),
        capabilities=frozenset({Capability.PLAN_ASSESSMENT}),
        mode=EngagementMode.DRY_RUN,
        created_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )
    policy.store.save_engagement(expired)
    with pytest.raises(AuthorizationError, match="expired"):
        policy.authorize(
            engagement_id="expired",
            capability=Capability.PLAN_ASSESSMENT,
            target="example.com",
        )

    active = policy.create_engagement(
        title="Active",
        ticket="SEC-2",
        targets=["example.com"],
        capabilities=["plan:assessment"],
    )
    policy.store.revoke_engagement(active.id)
    with pytest.raises(AuthorizationError, match="revoked"):
        policy.authorize(
            engagement_id=active.id,
            capability=Capability.PLAN_ASSESSMENT,
            target="example.com",
        )


@pytest.mark.parametrize(
    "change",
    [
        {"title": ""},
        {"ticket": ""},
        {"targets": []},
        {"capabilities": []},
        {"capabilities": ["unknown"]},
        {"mode": "unsafe"},
        {"expires_in_minutes": 0},
        {"expires_in_minutes": 1441},
    ],
)
def test_create_engagement_validates_contract(tmp_path, change):
    policy = _policy(tmp_path)
    values = {
        "title": "Review",
        "ticket": "SEC-42",
        "targets": ["example.com"],
        "capabilities": ["plan:assessment"],
        "mode": "dry-run",
        "expires_in_minutes": 60,
    }
    with pytest.raises(ValueError):
        policy.create_engagement(**{**values, **change})


def test_scope_check_records_result(tmp_path):
    policy = _policy(tmp_path)
    engagement = policy.create_engagement(
        title="Review",
        ticket="SEC-42",
        targets=["example.com"],
        capabilities=["plan:assessment"],
    )
    result = policy.scope_check(engagement.id, "other.example")
    assert result["in_scope"] is False
