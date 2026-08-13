"""Digest-bound compilation of raw-free multi-turn UX evidence."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from typing import Any

from outctl.contracts import ContractValidationError, validate_contract
from outctl.serialization import sha256_hex


class UxCompileError(ValueError):
    """Raised when UX observations are unbound, unsafe, or incomplete."""


def _canonical_digest(value: Mapping[str, Any], *, omit: str) -> str:
    # Deliberately not outctl.serialization.canonical_json_bytes: this digest
    # binds against a producer contract that does not drop None values, and
    # changing that would break existing digest bytes. See P0.3 in
    # docs/plans/agentops/ecosystem-simplification-plan.md.
    body = {key: item for key, item in value.items() if key != omit}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + sha256_hex(encoded)


def _count(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise UxCompileError(f"{name} must be a non-negative integer")
    return value


def compile_ux_evidence(
    task_protocol: Mapping[str, Any], observations: Mapping[str, Any]
) -> dict[str, Any]:
    """Compile session counters only after protocol and observation digest checks."""
    protocol_digest = task_protocol.get("protocol_digest")
    if not isinstance(protocol_digest, str) or protocol_digest != _canonical_digest(
        task_protocol, omit="protocol_digest"
    ):
        raise UxCompileError("task protocol digest does not bind canonical bytes")
    if observations.get("task_protocol_digest") != protocol_digest:
        raise UxCompileError("UX observations do not bind the selected task protocol")
    observation_digest = observations.get("observation_digest")
    if not isinstance(observation_digest, str) or observation_digest != _canonical_digest(
        observations, omit="observation_digest"
    ):
        raise UxCompileError("UX observation digest does not bind canonical bytes")
    session_id = observations.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise UxCompileError("session_id is required")
    turns = observations.get("turns")
    if not isinstance(turns, list) or len(turns) < 2:
        raise UxCompileError("UX evidence requires at least two turns")

    totals = Counter[str]()
    bypasses = Counter[str]()
    for index, turn in enumerate(turns):
        if not isinstance(turn, Mapping):
            raise UxCompileError(f"turns[{index}] must be an object")
        for name in (
            "logical_commands",
            "cluster_calls",
            "retrievals",
            "retrievals_contributing_to_findings",
            "reruns_avoided",
        ):
            totals[name] += _count(turn.get(name), f"turns[{index}].{name}")
        references = turn.get("evidence_refs")
        findings = _count(turn.get("findings"), f"turns[{index}].findings")
        checks = _count(turn.get("checks"), f"turns[{index}].checks")
        if not isinstance(references, list) or not all(
            isinstance(item, str) and item.startswith(("outctl://capture/", "artifact:sha256:"))
            for item in references
        ):
            raise UxCompileError(f"turns[{index}].evidence_refs are invalid")
        if findings + checks > 0 and not references:
            raise UxCompileError(f"turns[{index}] has uncited findings or checks")
        raw_bypasses = turn.get("bypasses", [])
        if not isinstance(raw_bypasses, list):
            raise UxCompileError(f"turns[{index}].bypasses must be an array")
        for reason in raw_bypasses:
            if not isinstance(reason, str) or not reason:
                raise UxCompileError(f"turns[{index}] contains an invalid bypass reason")
            bypasses[reason] += 1
    if totals["retrievals_contributing_to_findings"] > totals["retrievals"]:
        raise UxCompileError("contributing retrievals exceed total retrievals")
    generated_at = observations.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise UxCompileError("generated_at must be frozen by the observation set")
    evidence = {
        "schema_version": "vuoro.outctl.ux-evidence/v1",
        "task_protocol_digest": protocol_digest,
        "session_id_sha256": sha256_hex(session_id.encode()),
        "turns": len(turns),
        "logical_commands": totals["logical_commands"],
        "cluster_calls": totals["cluster_calls"],
        "retrievals": totals["retrievals"],
        "retrievals_contributing_to_findings": totals["retrievals_contributing_to_findings"],
        "reruns_avoided": totals["reruns_avoided"],
        "bypasses": [
            {"reason": reason, "count": count} for reason, count in sorted(bypasses.items())
        ],
        "quality_preserved": observations.get("quality_preserved") is True,
        "additional_critical_misses": _count(
            observations.get("additional_critical_misses"), "additional_critical_misses"
        ),
        "evidence_references_valid": True,
        "generated_at": generated_at,
    }
    try:
        return validate_contract("ux-evidence", evidence)
    except ContractValidationError as exc:
        raise UxCompileError(str(exc)) from exc
