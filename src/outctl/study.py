"""Deterministic, raw-free compilers for controlled-study evidence."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from outctl.contracts import ContractValidationError, validate_contract


class StudyCompileError(ValueError):
    """Raised when study observations cannot produce trustworthy analysis."""


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise StudyCompileError(f"{name} must be an integer >= {minimum}")
    return value


def _ppm_reduction(treatment: int, control: int) -> int | None:
    if control == 0:
        return None
    return round((control - treatment) * 1_000_000 / control)


def _median(values: Sequence[int]) -> int | None:
    return round(statistics.median(values)) if values else None


def _geometric_ratio_ppm(pairs: Sequence[tuple[int, int]]) -> int | None:
    ratios = [treatment / control for treatment, control in pairs if control > 0]
    if not ratios:
        return None
    if any(ratio == 0 for ratio in ratios):
        return 0
    return round(math.exp(sum(math.log(ratio) for ratio in ratios) / len(ratios)) * 1_000_000)


def compile_study_analysis(
    protocol: Mapping[str, Any],
    observations: Mapping[str, Any],
    *,
    analysis_code: Path | None = None,
) -> dict[str, Any]:
    """Compile frozen paired observations without excluding diagnostic disagreement."""
    validate_contract("study-protocol", protocol)
    dataset_class = observations.get("dataset_class")
    if dataset_class not in {"variance-pilot", "confirmatory"}:
        raise StudyCompileError("dataset_class must be variance-pilot or confirmatory")
    generated_at = observations.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise StudyCompileError("generated_at must be frozen by the observation set")
    raw_pairs = observations.get("pairs")
    if not isinstance(raw_pairs, list) or not raw_pairs:
        raise StudyCompileError("pairs must be a non-empty array")

    compiled: list[dict[str, Any]] = []
    valid_output: list[int] = []
    valid_uncached: list[int] = []
    output_ratios: list[tuple[int, int]] = []
    quality_differences: list[int] = []
    pooled = {
        "command_output_a": 0,
        "command_output_b": 0,
        "uncached_read_a": 0,
        "uncached_read_b": 0,
    }
    seen: set[str] = set()
    for index, item in enumerate(raw_pairs):
        if not isinstance(item, Mapping):
            raise StudyCompileError(f"pairs[{index}] must be an object")
        pair_id = item.get("pair_id")
        scenario_id = item.get("scenario_id")
        if not isinstance(pair_id, str) or not pair_id or pair_id in seen:
            raise StudyCompileError("pair_id values must be non-empty and unique")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise StudyCompileError(f"{pair_id}.scenario_id is required")
        seen.add(pair_id)
        protocol_valid = item.get("protocol_valid") is True
        identity_match = item.get("identity_binding_match") is True
        quality_a = item.get("quality_score_a_ppm")
        quality_b = item.get("quality_score_b_ppm")
        for name, score in (("quality_score_a_ppm", quality_a), ("quality_score_b_ppm", quality_b)):
            if score is not None and (
                not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 1_000_000
            ):
                raise StudyCompileError(f"{pair_id}.{name} is invalid")
        output_a = _integer(item.get("command_output_bytes_a"), f"{pair_id}.command_output_bytes_a")
        output_b = _integer(item.get("command_output_bytes_b"), f"{pair_id}.command_output_bytes_b")
        uncached_a = _integer(
            item.get("uncached_read_tokens_a"), f"{pair_id}.uncached_read_tokens_a"
        )
        uncached_b = _integer(
            item.get("uncached_read_tokens_b"), f"{pair_id}.uncached_read_tokens_b"
        )
        output_reduction = _ppm_reduction(output_a, output_b)
        uncached_reduction = _ppm_reduction(uncached_a, uncached_b)
        compiled.append(
            {
                "pair_id": pair_id,
                "scenario_id": scenario_id,
                "starting_arm": item.get("starting_arm"),
                "cache_stratum": item.get("cache_stratum"),
                "protocol_valid": protocol_valid,
                "identity_binding_match": identity_match,
                "quality_score_a_ppm": quality_a,
                "quality_score_b_ppm": quality_b,
                "critical_miss_a": item.get("critical_miss_a"),
                "critical_miss_b": item.get("critical_miss_b"),
                "command_output_reduction_ppm": output_reduction,
                "uncached_read_reduction_ppm": uncached_reduction,
            }
        )
        if protocol_valid:
            if not identity_match:
                raise StudyCompileError(f"protocol-valid pair {pair_id} has identity mismatch")
            if output_reduction is not None:
                valid_output.append(output_reduction)
                output_ratios.append((output_a, output_b))
            if uncached_reduction is not None:
                valid_uncached.append(uncached_reduction)
            if isinstance(quality_a, int) and isinstance(quality_b, int):
                quality_differences.append(quality_a - quality_b)
            pooled["command_output_a"] += output_a
            pooled["command_output_b"] += output_b
            pooled["uncached_read_a"] += uncached_a
            pooled["uncached_read_b"] += uncached_b

    valid = [pair for pair in compiled if pair["protocol_valid"] is True]
    margin = protocol.get("noninferiority_margin_ppm")
    quality_noninferior = (
        min(quality_differences) >= -int(margin)
        if quality_differences and isinstance(margin, int)
        else None
    )
    additional_misses = sum(
        pair["critical_miss_a"] is True and pair["critical_miss_b"] is False for pair in valid
    )
    source = analysis_code or Path(__file__)
    analysis = {
        "schema_version": "vuoro.outctl.study-analysis/v1",
        "protocol_digest": protocol["protocol_digest"],
        "analysis_code_digest": "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
        "dataset_class": dataset_class,
        "pairs": compiled,
        "paired_summary": {
            "protocol_valid_pairs": len(valid),
            "median_command_output_reduction_ppm": _median(valid_output),
            "geometric_mean_command_output_ratio_ppm": _geometric_ratio_ppm(output_ratios),
            "median_uncached_read_reduction_ppm": _median(valid_uncached),
            "quality_noninferior": quality_noninferior,
            "additional_critical_misses": additional_misses,
        },
        "pooled_secondary": pooled,
        "gate_results": {
            "quality_noninferior": quality_noninferior is True,
            "zero_additional_critical_misses": additional_misses == 0,
            "sample_size_reached": len(valid)
            >= int(
                protocol["confirmatory_pairs"]
                if dataset_class == "confirmatory"
                else protocol["variance_pilot_pairs"]
            ),
        },
        "generated_at": generated_at,
    }
    try:
        return validate_contract("study-analysis", analysis)
    except ContractValidationError as exc:
        raise StudyCompileError(str(exc)) from exc


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StudyCompileError(f"{path} must contain a JSON object")
    return value
