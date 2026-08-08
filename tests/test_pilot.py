from __future__ import annotations

import pytest

from outctl.pilot import PilotReportError, validate_pilot_report


def report() -> dict[str, object]:
    return {
        "pilot": {
            "harness": "codex",
            "command_class": "appservice-health-check",
            "policy_digest": "sha256:" + "a" * 64,
        },
        "baseline": {"exposed_tokens": 900},
        "enforce": {
            "raw_tokens": 1200,
            "exposed_tokens": 300,
            "retrieved_tokens": 80,
            "retrieval_count": 1,
            "wall_time_ms": 1200,
            "wrapper_overhead_ms": 90,
        },
        "assessment": {
            "harness_native_context_management": "limited visible truncation",
            "outctl_increment": "bounded retrieval available",
            "recommendation": "continue pilot",
        },
    }


def test_validates_qualitative_pilot_without_raw_bodies() -> None:
    summary = validate_pilot_report(report())
    assert summary.harness == "codex"
    assert summary.retrieval_count == 1


def test_rejects_raw_or_model_body_fields() -> None:
    value = report()
    value["raw_output"] = "must-not-be-recorded"
    with pytest.raises(PilotReportError, match="forbidden"):
        validate_pilot_report(value)


def test_requires_subjective_and_objective_evidence() -> None:
    value = report()
    del value["assessment"]
    with pytest.raises(PilotReportError, match="assessment"):
        validate_pilot_report(value)
