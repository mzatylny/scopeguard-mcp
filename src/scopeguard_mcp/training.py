"""Offline, non-operational security training scenarios."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

TRAINING_TARGET = "training.invalid"
_DIFFICULTIES = frozenset({"beginner", "intermediate", "advanced"})

_SCENARIOS: dict[str, dict[str, Any]] = {
    "exposed-service": {
        "title": "Unexpected exposed service",
        "learning_objective": (
            "Recognize exposure evidence, validate ownership, and choose containment without "
            "interacting with the service."
        ),
        "phases": [
            {
                "name": "synthetic-discovery",
                "simulated_event": "A training asset inventory reports an unexpected listener.",
                "defensive_signal": "The observed port is absent from the approved service map.",
                "defensive_action": "Confirm asset ownership and compare against the change record.",
            },
            {
                "name": "synthetic-pressure",
                "simulated_event": "The scenario marks repeated access-interest around the service.",
                "defensive_signal": "Connection telemetry increases without an approved test window.",
                "defensive_action": "Restrict exposure and preserve relevant network evidence.",
            },
            {
                "name": "recovery-review",
                "simulated_event": "Containment is recorded in the tabletop timeline.",
                "defensive_signal": "The listener is no longer visible in the synthetic inventory.",
                "defensive_action": "Verify the intended service baseline and document prevention work.",
            },
        ],
    },
    "web-hardening": {
        "title": "Web hardening gap",
        "learning_objective": (
            "Interpret defensive HTTP and TLS findings and prioritize configuration remediation."
        ),
        "phases": [
            {
                "name": "synthetic-observation",
                "simulated_event": "A training report flags weak browser-security policy coverage.",
                "defensive_signal": "Expected security headers are missing from the fixture.",
                "defensive_action": "Classify the gap and identify the responsible configuration owner.",
            },
            {
                "name": "risk-review",
                "simulated_event": "The tabletop assumes a user visits untrusted content.",
                "defensive_signal": "The fixture lacks a compensating browser policy.",
                "defensive_action": "Prioritize a restrictive policy and regression coverage.",
            },
            {
                "name": "control-validation",
                "simulated_event": "A corrected response is inserted into the offline fixture.",
                "defensive_signal": "The expected header inventory now matches the baseline.",
                "defensive_action": "Record evidence and schedule a configuration drift check.",
            },
        ],
    },
    "repository-secret": {
        "title": "Synthetic repository secret exposure",
        "learning_objective": (
            "Practice safe secret-response decisions without displaying or using a credential."
        ),
        "phases": [
            {
                "name": "synthetic-alert",
                "simulated_event": "A fixture scanner reports a fingerprinted secret-like value.",
                "defensive_signal": "Only a rule ID, location, and one-way fingerprint are available.",
                "defensive_action": "Treat the value as exposed and identify its owning system.",
            },
            {
                "name": "containment-decision",
                "simulated_event": "The tabletop marks the credential as potentially copied.",
                "defensive_signal": "Repository history may retain the synthetic exposure marker.",
                "defensive_action": "Revoke the credential and preserve evidence before cleanup.",
            },
            {
                "name": "prevention-review",
                "simulated_event": "Rotation and repository remediation are recorded as complete.",
                "defensive_signal": "The fixture scan is clean and the old fingerprint is denied.",
                "defensive_action": "Add preventive scanning and verify least-privilege issuance.",
            },
        ],
    },
}

_PROMPTS = {
    "beginner": "Which defensive signal matters most, and who should own the next action?",
    "intermediate": "What evidence supports the action, and what false positive should be excluded?",
    "advanced": "How would you validate containment and detect recurrence without expanding scope?",
}


def simulate_training_scenario(scenario: str, difficulty: str) -> dict[str, Any]:
    """Return a deterministic tabletop trace; never touch a real target or runtime."""
    scenario_key = scenario.strip().lower()
    difficulty_key = difficulty.strip().lower()
    if scenario_key not in _SCENARIOS:
        supported = ", ".join(sorted(_SCENARIOS))
        raise ValueError(f"unknown training scenario; choose one of: {supported}")
    if difficulty_key not in _DIFFICULTIES:
        raise ValueError("difficulty must be beginner, intermediate, or advanced")
    content = deepcopy(_SCENARIOS[scenario_key])
    for index, phase in enumerate(content["phases"], start=1):
        phase["sequence"] = index
        phase["learner_prompt"] = _PROMPTS[difficulty_key]
    return {
        "simulation": True,
        "operational": False,
        "target": TRAINING_TARGET,
        "scenario": scenario_key,
        "difficulty": difficulty_key,
        **content,
        "guardrails": {
            "network_access": False,
            "filesystem_access": False,
            "commands": False,
            "payloads": False,
            "credentials": False,
            "real_targets": False,
            "dynamic_attack_selection": False,
        },
    }
