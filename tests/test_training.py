import pytest

from scopeguard_mcp.training import TRAINING_TARGET, simulate_training_scenario


def test_training_scenario_is_offline_non_operational_and_deterministic():
    first = simulate_training_scenario("web-hardening", "advanced")
    second = simulate_training_scenario("web-hardening", "advanced")
    assert first == second
    assert first["target"] == TRAINING_TARGET
    assert first["simulation"] is True
    assert first["operational"] is False
    assert all(value is False for value in first["guardrails"].values())
    assert [phase["sequence"] for phase in first["phases"]] == [1, 2, 3]


@pytest.mark.parametrize(
    "scenario",
    ["exposed-service", "web-hardening", "repository-secret"],
)
def test_supported_scenarios_are_defensive_tabletops(scenario):
    result = simulate_training_scenario(scenario, "beginner")
    assert len(result["phases"]) == 3
    for phase in result["phases"]:
        assert set(phase) == {
            "name",
            "simulated_event",
            "defensive_signal",
            "defensive_action",
            "sequence",
            "learner_prompt",
        }


def test_training_scenario_rejects_unknown_inputs():
    with pytest.raises(ValueError, match="unknown training scenario"):
        simulate_training_scenario("real-target", "beginner")
    with pytest.raises(ValueError, match="difficulty"):
        simulate_training_scenario("web-hardening", "expert")
