from __future__ import annotations

from copy import deepcopy

import pytest

from outctl.contracts import _canonical_digest
from outctl.study import StudyCompileError, compile_study_analysis


def _protocol() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "vuoro.outctl.study-protocol/v2",
        "protocol_id": "test",
        "protocol_digest": "",
        "frozen_at": "2026-08-09T00:00:00Z",
        "repository_commit": "a" * 40,
        "study_suite_path": "studies/suite.json",
        "study_suite_digest": "sha256:" + "b" * 64,
        "quality_scoring_version": "expected-fact-recall/v1",
        "noninferiority_margin_ppm": 50_000,
        "critical_severities": ["critical", "high"],
        "variance_pilot_pairs": 6,
        "confirmatory_pairs": 3,
        "randomization_seed": 7,
        "cache_strata": ["cold", "warm", "unknown"],
        "primary_outcomes": [
            "diagnostic_quality_noninferiority",
            "additional_critical_misses",
            "model_visible_command_output_bytes",
            "uncached_read_input_tokens",
        ],
        "secondary_outcomes": ["latency_ms"],
        "exclusion_rules": ["protocol-invalid"],
        "stopping_rules": ["stop on identity mismatch"],
    }
    value["protocol_digest"] = _canonical_digest(value, omit="protocol_digest")
    return value


def _observations() -> dict[str, object]:
    base = {
        "scenario_id": "healthy",
        "starting_arm": "A",
        "cache_stratum": "cold",
        "protocol_valid": True,
        "identity_binding_match": True,
        "quality_score_a_ppm": 950_000,
        "quality_score_b_ppm": 970_000,
        "critical_miss_a": False,
        "critical_miss_b": False,
        "command_output_bytes_a": 40,
        "command_output_bytes_b": 100,
        "uncached_read_tokens_a": 60,
        "uncached_read_tokens_b": 100,
    }
    return {
        "dataset_class": "variance-pilot",
        "generated_at": "2026-08-09T01:00:00Z",
        "pairs": [
            {**base, "pair_id": f"p{index}", "starting_arm": "A" if index % 2 else "B"}
            for index in range(1, 7)
        ],
    }


def test_compile_study_analysis_is_deterministic_and_paired() -> None:
    first = compile_study_analysis(_protocol(), _observations())
    second = compile_study_analysis(_protocol(), _observations())
    assert first == second
    assert first["paired_summary"] == {
        "protocol_valid_pairs": 6,
        "median_command_output_reduction_ppm": 600_000,
        "geometric_mean_command_output_ratio_ppm": 400_000,
        "median_uncached_read_reduction_ppm": 400_000,
        "quality_noninferior": True,
        "additional_critical_misses": 0,
    }
    assert first["gate_results"]["sample_size_reached"] is True


def test_diagnostic_disagreement_does_not_exclude_protocol_valid_pair() -> None:
    observations = _observations()
    observations["pairs"][0]["quality_score_a_ppm"] = 500_000  # type: ignore[index]
    result = compile_study_analysis(_protocol(), observations)
    assert result["paired_summary"]["protocol_valid_pairs"] == 6
    assert result["paired_summary"]["quality_noninferior"] is False


def test_protocol_valid_identity_mismatch_fails_closed() -> None:
    observations = deepcopy(_observations())
    observations["pairs"][0]["identity_binding_match"] = False  # type: ignore[index]
    with pytest.raises(StudyCompileError, match="identity mismatch"):
        compile_study_analysis(_protocol(), observations)


def test_non_alternating_pair_order_fails_closed() -> None:
    observations = _observations()
    observations["pairs"][1]["starting_arm"] = "A"  # type: ignore[index]
    with pytest.raises(StudyCompileError, match="must alternate"):
        compile_study_analysis(_protocol(), observations)
