"""Machine-readable enablement stage evaluation.

The evaluator consumes metadata evidence only.  It never runs commands,
changes adapter mode, or mutates action/audit/policy authorities.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

RAW_KEYS = frozenset(
    {"stdout", "stderr", "raw_output", "projection_body", "events_jsonl", "tool_body"}
)


class EnablementEvidenceError(ValueError):
    """Raised when stage evidence is unsafe or malformed."""


@dataclass(frozen=True)
class StageResult:
    stage: int
    name: str
    passed: bool
    checks: dict[str, bool]
    external: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "name": self.name,
            "passed": self.passed,
            "external": self.external,
            "checks": self.checks,
        }


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EnablementEvidenceError(f"{name} must be an object")
    return value


def _bool(value: Mapping[str, Any], key: str) -> bool:
    return value.get(key) is True


def _number(value: Mapping[str, Any], key: str) -> float | None:
    item = value.get(key)
    if isinstance(item, (int, float)) and not isinstance(item, bool):
        return float(item)
    return None


def _reject_raw(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.casefold() in RAW_KEYS:
                raise EnablementEvidenceError(f"raw body key is forbidden at {path}.{key}")
            _reject_raw(item, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, item in enumerate(value):
            _reject_raw(item, f"{path}[{index}]")


def _stage(
    stage: int, name: str, checks: dict[str, bool], *, external: bool = False
) -> StageResult:
    return StageResult(stage, name, bool(checks) and all(checks.values()), checks, external)


def evaluate_enablement(evidence: Mapping[str, Any]) -> dict[str, object]:
    """Evaluate ordered enablement gates without treating missing evidence as success."""
    _reject_raw(evidence)
    foundation = _mapping(evidence.get("foundation", {}), "foundation")
    mechanism = _mapping(evidence.get("mechanism", {}), "mechanism")
    identity = _mapping(evidence.get("identity_boundary", {}), "identity_boundary")
    shadow = _mapping(evidence.get("shadow", {}), "shadow")
    controlled = _mapping(evidence.get("controlled_study", {}), "controlled_study")
    ux = _mapping(evidence.get("ux_pilot", {}), "ux_pilot")
    enforce = _mapping(evidence.get("selected_enforcement", {}), "selected_enforcement")
    authority = _mapping(evidence.get("authority_integration", {}), "authority_integration")
    second = _mapping(evidence.get("second_harness", {}), "second_harness")
    hybrid = _mapping(evidence.get("hybrid", {}), "hybrid")

    receipts = identity.get("paired_receipts")
    receipt_list = receipts if isinstance(receipts, list) else []
    identity_receipts_valid = bool(receipt_list) and all(
        isinstance(pair, Mapping)
        and pair.get("a") == pair.get("b")
        and isinstance(pair.get("a"), str)
        and len(pair["a"]) == 64
        for pair in receipt_list
    )
    pairs = _number(controlled, "protocol_valid_pairs")
    output_reduction = _number(controlled, "median_command_output_reduction_pct")
    stages = [
        _stage(
            0,
            "contracts-and-fixtures",
            {
                "schemas_valid": _bool(foundation, "schemas_valid"),
                "policy_digest_stable": _bool(foundation, "policy_digest_stable"),
                "full_repository_gate": _bool(foundation, "full_repository_gate"),
            },
        ),
        _stage(
            1,
            "local-capture-mechanism",
            {
                "benchmark_passed": _bool(mechanism, "passed"),
                "process_semantics_passed": _bool(mechanism, "process_semantics_passed"),
                "security_passed": _bool(mechanism, "security_passed"),
            },
        ),
        _stage(
            2,
            "runner-owned-identity-boundary",
            {
                "direct_argv": _bool(identity, "direct_argv"),
                "runner_injected": identity.get("identity_source") == "runner_injected",
                "paired_bindings_match": identity_receipts_valid,
                "read_only_rbac": _bool(identity, "read_only_rbac"),
            },
        ),
        _stage(
            3,
            "shadow-enablement",
            {
                "semantic_equivalence": _bool(shadow, "semantic_equivalence"),
                "no_deadlocks": _bool(shadow, "no_deadlocks"),
                "recovery_verified": _bool(shadow, "recovery_verified"),
                "overhead_acceptable": _bool(shadow, "overhead_acceptable"),
            },
        ),
        _stage(
            4,
            "controlled-efficacy",
            {
                "frozen_protocol": _bool(controlled, "frozen_protocol"),
                "sufficient_pairs": pairs is not None and pairs >= 18,
                "quality_noninferior": _bool(controlled, "quality_noninferior"),
                "zero_additional_critical_misses": _bool(
                    controlled, "zero_additional_critical_misses"
                ),
                "output_reduction": output_reduction is not None and output_reduction >= 50,
            },
        ),
        _stage(
            5,
            "real-ux-pilot",
            {
                "multi_turn": _bool(ux, "multi_turn"),
                "quality_preserved": _bool(ux, "quality_preserved"),
                "retrieval_contributed": _bool(ux, "retrieval_contributed"),
                "raw_free_report": _bool(ux, "raw_free_report"),
            },
        ),
        _stage(
            6,
            "selected-enforcement",
            {
                "approved_command_classes": _bool(enforce, "approved_command_classes"),
                "rollback_verified": _bool(enforce, "rollback_verified"),
                "redaction_verified": _bool(enforce, "redaction_verified"),
                "bypass_pressure_acceptable": _bool(enforce, "bypass_pressure_acceptable"),
            },
        ),
        _stage(
            7,
            "authority-and-second-harness",
            {
                "action_receipts": _bool(authority, "action_receipts"),
                "audit_verification": _bool(authority, "audit_verification"),
                "policy_promoted": _bool(authority, "policy_promoted"),
                "second_harness_conformant": _bool(second, "conformant"),
            },
            external=True,
        ),
        _stage(
            8,
            "hybrid-portability",
            {
                "replica_classes_preserved": _bool(hybrid, "replica_classes_preserved"),
                "cross_host_verified": _bool(hybrid, "cross_host_verified"),
                "local_break_glass": _bool(hybrid, "local_break_glass"),
            },
            external=True,
        ),
    ]
    contiguous = -1
    for result in stages:
        if not result.passed:
            break
        contiguous = result.stage
    next_stage = next((result for result in stages if not result.passed), None)
    return {
        "schema_version": "outctl.enablement-evidence/v1",
        "highest_contiguous_stage": contiguous,
        "next_stage": next_stage.to_dict() if next_stage else None,
        "stages": [result.to_dict() for result in stages],
        "fully_enabled": contiguous == stages[-1].stage,
    }
