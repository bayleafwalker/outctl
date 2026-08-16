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
    if protocol.get("schema_version") == "vuoro.outctl.study-protocol/v3":
        return _compile_n_arm_analysis(protocol, observations, analysis_code=analysis_code)
    if protocol.get("schema_version") in {
        "vuoro.outctl.study-protocol/v1",
        "vuoro.outctl.study-protocol/v2",
    }:
        raise StudyCompileError(
            "historical study protocols are recorded results, not v3 recompilation targets"
        )
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


def _compile_n_arm_analysis(
    protocol: Mapping[str, Any],
    observations: Mapping[str, Any],
    *,
    analysis_code: Path | None,
) -> dict[str, Any]:
    """Compile v3 session records by declared contrasts.

    This deliberately has no adapter from the historical ``pairs`` shape.
    A v3 run must emit arm-keyed sessions, and old proof artifacts remain
    recorded results rather than being reinterpreted as v3 observations.
    """
    try:
        checked = validate_contract("study-protocol", protocol)
    except ContractValidationError as exc:
        raise StudyCompileError(str(exc)) from exc
    dataset_class = observations.get("dataset_class")
    if dataset_class not in {"variance-pilot", "confirmatory"}:
        raise StudyCompileError("dataset_class must be variance-pilot or confirmatory")
    generated_at = observations.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise StudyCompileError("generated_at must be frozen by the observation set")
    raw_sessions = observations.get("sessions")
    if not isinstance(raw_sessions, list) or not raw_sessions:
        raise StudyCompileError("v3 observations must contain a non-empty sessions array")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    groups: dict[tuple[str, int, str], dict[str, dict[str, Any]]] = {}
    for index, item in enumerate(raw_sessions):
        if not isinstance(item, Mapping):
            raise StudyCompileError(f"sessions[{index}] must be an object")
        session_id = item.get("session_id")
        if not isinstance(session_id, str) or not session_id or session_id in seen:
            raise StudyCompileError("session_id values must be non-empty and unique")
        seen.add(session_id)
        required_strings = ("scenario_id", "arm_id", "start_group")
        if any(
            not isinstance(item.get(name), str) or not item.get(name) for name in required_strings
        ):
            raise StudyCompileError(f"{session_id} has an invalid scenario, arm, or start group")
        replicate = item.get("replicate")
        start_order = item.get("start_order")
        if not isinstance(replicate, int) or isinstance(replicate, bool) or replicate < 1:
            raise StudyCompileError(f"{session_id}.replicate must be positive")
        if not isinstance(start_order, int) or isinstance(start_order, bool) or start_order < 0:
            raise StudyCompileError(f"{session_id}.start_order must be non-negative")
        for name in ("command_event_aggregated_output_bytes", "uncached_read_input_tokens"):
            value = item.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise StudyCompileError(f"{session_id}.{name} must be a non-negative integer")
        quality = item.get("quality_score_ppm")
        if quality is not None and (
            not isinstance(quality, int)
            or isinstance(quality, bool)
            or not 0 <= quality <= 1_000_000
        ):
            raise StudyCompileError(f"{session_id}.quality_score_ppm is invalid")
        if not isinstance(item.get("protocol_valid"), bool) or not isinstance(
            item.get("identity_binding_match"), bool
        ):
            raise StudyCompileError(f"{session_id} validity fields must be boolean")
        miss = item.get("critical_miss")
        if miss is not None and not isinstance(miss, bool):
            raise StudyCompileError(f"{session_id}.critical_miss must be boolean or null")
        normalized_item = {
            "session_id": session_id,
            "scenario_id": item["scenario_id"],
            "arm_id": item["arm_id"],
            "replicate": replicate,
            "start_group": item["start_group"],
            "start_order": start_order,
            "protocol_valid": item["protocol_valid"],
            "identity_binding_match": item["identity_binding_match"],
            "quality_score_ppm": quality,
            "critical_miss": miss,
            "command_event_aggregated_output_bytes": item["command_event_aggregated_output_bytes"],
            "uncached_read_input_tokens": item["uncached_read_input_tokens"],
        }
        normalized.append(normalized_item)
        key = (str(item["scenario_id"]), replicate, str(item["start_group"]))
        by_arm = groups.setdefault(key, {})
        arm_id = str(item["arm_id"])
        if arm_id in by_arm:
            raise StudyCompileError(
                f"start group {item['start_group']} contains duplicate arm {arm_id}"
            )
        by_arm[arm_id] = normalized_item

    declared_arm_ids = checked.get("arm_ids")
    if not isinstance(declared_arm_ids, list) or not all(
        isinstance(arm_id, str) for arm_id in declared_arm_ids
    ):
        raise StudyCompileError("v3 protocol arm_ids are invalid")
    for group_id, by_arm in groups.items():
        if set(by_arm) != set(declared_arm_ids):
            raise StudyCompileError(
                f"start group {group_id[2]} does not contain the sealed arm set"
            )
        orders = sorted(int(item["start_order"]) for item in by_arm.values())
        if orders != list(range(len(declared_arm_ids))):
            raise StudyCompileError(f"start group {group_id[2]} has an invalid start order")

    contrasts = checked.get("contrasts")
    if not isinstance(contrasts, list) or not contrasts:
        raise StudyCompileError("v3 protocol must declare at least one contrast")
    margin = checked.get("noninferiority_margin_ppm")
    assert isinstance(margin, int)
    contrast_results: list[dict[str, Any]] = []
    pooled: dict[str, int] = {}
    any_valid_group = False
    for contrast in contrasts:
        if not isinstance(contrast, Mapping):
            raise StudyCompileError("protocol contrast must be an object")
        contrast_id = contrast.get("contrast_id")
        treatment = contrast.get("treatment_arm")
        control = contrast.get("control_arm")
        if not isinstance(contrast_id, str) or not contrast_id:
            raise StudyCompileError("protocol contrast is incomplete")
        if not isinstance(treatment, str) or not treatment:
            raise StudyCompileError("protocol contrast is incomplete")
        if not isinstance(control, str) or not control:
            raise StudyCompileError("protocol contrast is incomplete")
        output_reductions: list[int] = []
        uncached_reductions: list[int] = []
        quality_differences: list[int] = []
        additional_misses = 0
        valid_groups = 0
        for by_arm in groups.values():
            treated = by_arm.get(treatment)
            baseline = by_arm.get(control)
            if treated is None or baseline is None:
                continue
            if treated["protocol_valid"] and baseline["protocol_valid"]:
                if not treated["identity_binding_match"] or not baseline["identity_binding_match"]:
                    raise StudyCompileError(
                        f"protocol-valid contrast {contrast_id} has identity mismatch"
                    )
                valid_groups += 1
                any_valid_group = True
                output_reduction = _ppm_reduction(
                    int(treated["command_event_aggregated_output_bytes"]),
                    int(baseline["command_event_aggregated_output_bytes"]),
                )
                if output_reduction is not None:
                    output_reductions.append(output_reduction)
                uncached_reduction = _ppm_reduction(
                    int(treated["uncached_read_input_tokens"]),
                    int(baseline["uncached_read_input_tokens"]),
                )
                if uncached_reduction is not None:
                    uncached_reductions.append(uncached_reduction)
                if isinstance(treated["quality_score_ppm"], int) and isinstance(
                    baseline["quality_score_ppm"], int
                ):
                    quality_differences.append(
                        int(treated["quality_score_ppm"]) - int(baseline["quality_score_ppm"])
                    )
                if treated["critical_miss"] is True and baseline["critical_miss"] is False:
                    additional_misses += 1
                pooled[f"command_output_{treatment}"] = pooled.get(
                    f"command_output_{treatment}", 0
                ) + int(treated["command_event_aggregated_output_bytes"])
                pooled[f"command_output_{control}"] = pooled.get(
                    f"command_output_{control}", 0
                ) + int(baseline["command_event_aggregated_output_bytes"])
        quality_noninferior = min(quality_differences) >= -margin if quality_differences else None
        contrast_results.append(
            {
                "contrast_id": contrast_id,
                "treatment_arm": treatment,
                "control_arm": control,
                "protocol_valid_sessions": valid_groups,
                "median_output_reduction_ppm": _median(output_reductions),
                "median_uncached_read_reduction_ppm": _median(uncached_reductions),
                "quality_noninferior": quality_noninferior,
                "additional_critical_misses": additional_misses,
            }
        )
    required = int(checked["replicates"])
    analysis_source = analysis_code or Path(__file__)
    analysis = {
        "schema_version": "vuoro.outctl.study-analysis/v2",
        "protocol_digest": checked["protocol_digest"],
        "analysis_code_digest": "sha256:"
        + hashlib.sha256(analysis_source.read_bytes()).hexdigest(),
        "dataset_class": dataset_class,
        "sessions": normalized,
        "contrasts": contrast_results,
        "pooled_secondary": pooled,
        "gate_results": {
            "quality_noninferior": all(
                item["quality_noninferior"] is True for item in contrast_results
            ),
            "zero_additional_critical_misses": all(
                item["additional_critical_misses"] == 0 for item in contrast_results
            ),
            "sample_size_reached": any_valid_group
            and all(item["protocol_valid_sessions"] >= required for item in contrast_results),
        },
        "generated_at": generated_at,
    }
    try:
        return validate_contract("study-analysis-v2", analysis)
    except ContractValidationError as exc:
        raise StudyCompileError(str(exc)) from exc


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StudyCompileError(f"{path} must contain a JSON object")
    return value
