from __future__ import annotations

from copy import deepcopy

import pytest

from outctl.contracts import _canonical_digest
from outctl.study import StudyCompileError, compile_study_analysis


def _protocol() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "vuoro.outctl.study-protocol/v3",
        "protocol_id": "test",
        "protocol_digest": "",
        "digest_scope": "canonical-json-v1",
        "frozen_at": "2026-08-09T00:00:00Z",
        "repository_commit": "a" * 40,
        "scenario_suite_path": "scenarios/suite.json",
        "scenario_suite_digest": "sha256:" + "b" * 64,
        "arm_matrix_path": "scenarios/matrix.json",
        "arm_matrix_digest": "sha256:" + "c" * 64,
        "arm_ids": ["A", "B"],
        "contrasts": [{"contrast_id": "B_vs_A", "treatment_arm": "B", "control_arm": "A"}],
        "runner": "test-runner",
        "replicates": 6,
        "randomization_seed": 7,
        "limits": {"max_sessions": None, "max_concurrent_sessions": None, "max_credits": None},
        "estimated_credits_per_session": 0,
        "quality_scoring_version": "expected-fact-recall/v1",
        "noninferiority_margin_ppm": 50_000,
        "critical_severities": ["critical", "high"],
        "cache_strata": ["cold", "warm", "unknown"],
        "primary_outcomes": [
            "diagnostic_quality_noninferiority",
            "command_event_aggregated_output_bytes",
        ],
        "secondary_outcomes": ["latency_ms"],
        "exclusion_rules": ["protocol-invalid"],
        "stopping_rules": ["stop on identity mismatch"],
    }
    value["protocol_digest"] = _canonical_digest(value, omit="protocol_digest")
    return value


def _observations() -> dict[str, object]:
    sessions: list[dict[str, object]] = []
    for index in range(1, 7):
        group = f"healthy/r{index}"
        order = ["A", "B"] if index % 2 else ["B", "A"]
        values = {
            "A": (950_000, 40, 60, False),
            "B": (970_000, 100, 100, False),
        }
        for start_order, arm_id in enumerate(order):
            quality, output, uncached, critical_miss = values[arm_id]
            sessions.append(
                {
                    "session_id": f"{group}/{arm_id}",
                    "scenario_id": "healthy",
                    "arm_id": arm_id,
                    "replicate": index,
                    "start_group": group,
                    "start_order": start_order,
                    "protocol_valid": True,
                    "identity_binding_match": True,
                    "quality_score_ppm": quality,
                    "critical_miss": critical_miss,
                    "command_event_aggregated_output_bytes": output,
                    "uncached_read_input_tokens": uncached,
                }
            )
    return {
        "dataset_class": "variance-pilot",
        "generated_at": "2026-08-09T01:00:00Z",
        "sessions": sessions,
    }


def test_compile_study_analysis_is_deterministic_and_contrast_driven() -> None:
    first = compile_study_analysis(_protocol(), _observations())
    second = compile_study_analysis(_protocol(), _observations())
    assert first == second
    assert first["contrasts"] == [
        {
            "contrast_id": "B_vs_A",
            "treatment_arm": "B",
            "control_arm": "A",
            "protocol_valid_sessions": 6,
            "median_output_reduction_ppm": -1_500_000,
            "median_uncached_read_reduction_ppm": -666_667,
            "quality_noninferior": True,
            "additional_critical_misses": 0,
        }
    ]
    assert first["gate_results"]["sample_size_reached"] is True


def test_diagnostic_disagreement_does_not_exclude_protocol_valid_pair() -> None:
    observations = _observations()
    observations["sessions"][1]["quality_score_ppm"] = 500_000  # type: ignore[index]
    result = compile_study_analysis(_protocol(), observations)
    assert result["contrasts"][0]["protocol_valid_sessions"] == 6
    assert result["contrasts"][0]["quality_noninferior"] is False


def test_protocol_valid_identity_mismatch_fails_closed() -> None:
    observations = deepcopy(_observations())
    observations["sessions"][0]["identity_binding_match"] = False  # type: ignore[index]
    with pytest.raises(StudyCompileError, match="identity mismatch"):
        compile_study_analysis(_protocol(), observations)


def test_incomplete_start_group_fails_closed() -> None:
    observations = _observations()
    observations["sessions"].pop()  # type: ignore[union-attr]
    with pytest.raises(StudyCompileError, match="arm set"):
        compile_study_analysis(_protocol(), observations)
