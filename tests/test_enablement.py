from __future__ import annotations

import pytest

from outctl.enablement import EnablementEvidenceError, evaluate_enablement


def _evidence() -> dict[str, object]:
    digest = "a" * 64
    return {
        "foundation": {
            "schemas_valid": True,
            "policy_digest_stable": True,
            "full_repository_gate": True,
        },
        "mechanism": {
            "passed": True,
            "process_semantics_passed": True,
            "security_passed": True,
        },
        "identity_boundary": {
            "direct_argv": True,
            "identity_source": "runner_injected",
            "paired_receipts": [{"a": digest, "b": digest}],
            "read_only_rbac": True,
        },
        "shadow": {
            "semantic_equivalence": True,
            "no_deadlocks": True,
            "recovery_verified": True,
            "overhead_acceptable": True,
        },
        "controlled_study": {
            "frozen_protocol": True,
            "protocol_valid_pairs": 18,
            "quality_noninferior": True,
            "zero_additional_critical_misses": True,
            "median_command_output_reduction_pct": 84.0,
        },
        "ux_pilot": {
            "multi_turn": True,
            "quality_preserved": True,
            "retrieval_contributed": True,
            "raw_free_report": True,
        },
        "selected_enforcement": {
            "approved_command_classes": True,
            "rollback_verified": True,
            "redaction_verified": True,
            "bypass_pressure_acceptable": True,
        },
        "authority_integration": {},
        "second_harness": {},
        "hybrid": {},
    }


def test_enablement_stops_before_external_authority_integrations() -> None:
    result = evaluate_enablement(_evidence())
    assert result["highest_contiguous_stage"] == 6
    assert result["next_stage"]["external"] is True  # type: ignore[index]
    assert result["fully_enabled"] is False


def test_enablement_does_not_skip_an_unmet_ordered_gate() -> None:
    evidence = _evidence()
    evidence["shadow"] = {}
    result = evaluate_enablement(evidence)
    assert result["highest_contiguous_stage"] == 2
    assert result["next_stage"]["name"] == "shadow-enablement"  # type: ignore[index]


def test_enablement_rejects_raw_bodies() -> None:
    evidence = _evidence()
    evidence["ux_pilot"] = {"stdout": "secret"}
    with pytest.raises(EnablementEvidenceError, match="raw body"):
        evaluate_enablement(evidence)

