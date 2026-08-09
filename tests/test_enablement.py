from __future__ import annotations

import pytest

from outctl.enablement import EnablementEvidenceError, evaluate_enablement


def _evidence() -> dict[str, object]:
    digest = "a" * 64
    names = ("foundation", "mechanism", "identity", "shadow", "study", "ux", "enforce")
    artifacts = [
        {
            "evidence_id": name,
            "kind": name,
            "digest": f"sha256:{index:064x}",
            "classification": "metadata-only",
            "locator": f"artifact:sha256:{index:064x}",
        }
        for index, name in enumerate(names, start=1)
    ]
    return {
        "schema_version": "vuoro.outctl.enablement-evidence/v1",
        "packet_id": "test",
        "repository_commit": "a" * 40,
        "environment_id": "test",
        "authorization": {"class": "read-only-live", "reference": "test-auth"},
        "generated_at": "2026-08-09T00:00:00Z",
        "evidence": artifacts,
        "foundation": {
            "schemas_valid": True,
            "policy_digest_stable": True,
            "full_repository_gate": True,
            "evidence_ids": ["foundation"],
        },
        "mechanism": {
            "passed": True,
            "process_semantics_passed": True,
            "security_passed": True,
            "negative_tests_passed": True,
            "evidence_ids": ["mechanism"],
        },
        "identity_boundary": {
            "direct_argv": True,
            "identity_source": "runner_injected",
            "paired_receipts": [{"logical_command_id": "one", "a": digest, "b": digest}],
            "read_only_rbac": True,
            "negative_rbac_tests": True,
            "evidence_ids": ["identity"],
        },
        "shadow": {
            "semantic_equivalence": True,
            "no_deadlocks": True,
            "recovery_verified": True,
            "overhead_acceptable": True,
            "rollback_verified": True,
            "evidence_ids": ["shadow"],
        },
        "controlled_study": {
            "protocol_digest": "sha256:" + "b" * 64,
            "dataset_class": "confirmatory",
            "frozen_protocol": True,
            "protocol_valid_pairs": 18,
            "quality_noninferior": True,
            "zero_additional_critical_misses": True,
            "median_command_output_reduction_ppm": 840_000,
            "evidence_ids": ["study"],
        },
        "ux_pilot": {
            "multi_turn": True,
            "quality_preserved": True,
            "retrieval_contributed": True,
            "raw_free_report": True,
            "evidence_ids": ["ux"],
        },
        "selected_enforcement": {
            "approved_command_classes": True,
            "rollback_verified": True,
            "redaction_verified": True,
            "bypass_pressure_acceptable": True,
            "evidence_ids": ["enforce"],
        },
        "authority_integration": {
            "action_receipts": False,
            "audit_verification": False,
            "policy_promoted": False,
            "evidence_ids": [],
        },
        "second_harness": {"harness_id": None, "conformant": False, "evidence_ids": []},
        "hybrid": {
            "replica_classes_preserved": False,
            "cross_host_verified": False,
            "local_break_glass": False,
            "evidence_ids": [],
        },
    }


def test_enablement_stops_before_external_authority_integrations() -> None:
    result = evaluate_enablement(_evidence())
    assert result["highest_contiguous_stage"] == 6
    assert result["next_stage"]["external"] is True  # type: ignore[index]
    assert result["fully_enabled"] is False


def test_enablement_does_not_skip_an_unmet_ordered_gate() -> None:
    evidence = _evidence()
    evidence["shadow"]["semantic_equivalence"] = False  # type: ignore[index]
    result = evaluate_enablement(evidence)
    assert result["highest_contiguous_stage"] == 2
    assert result["next_stage"]["name"] == "shadow-enablement"  # type: ignore[index]


def test_enablement_rejects_raw_bodies() -> None:
    evidence = _evidence()
    evidence["ux_pilot"]["stdout"] = "secret"  # type: ignore[index]
    with pytest.raises(EnablementEvidenceError, match="raw or sensitive body"):
        evaluate_enablement(evidence)

