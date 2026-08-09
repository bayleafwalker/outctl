from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from outctl.contracts import (
    ContractValidationError,
    normalize_enablement_evidence,
    validate_contract,
)

ROOT = Path(__file__).parents[1]
DIGEST = "sha256:" + "a" * 64
SHA = "a" * 64


def test_checked_in_enablement_packet_validates_and_binds_evidence() -> None:
    value = json.loads((ROOT / "config/enablement-evidence.example.json").read_text())
    assert validate_contract("enablement-evidence", value)["packet_id"] == "example-offline-local"
    expected = json.loads(
        (ROOT / "acceptance/codex_appservice_ab/expected-facts.example.json").read_text()
    )
    validate_contract("expected-facts", expected)


def test_evidence_reference_rejects_reversed_range() -> None:
    reference = {
        "schema_version": "vuoro.outctl.evidence-reference/v1",
        "capture_ref": "outctl://capture/abc123/manifest/sha256/" + "a" * 64,
        "operation": "slice",
        "stream": "stdout",
        "start": 20,
        "end": 10,
        "query_digest": None,
        "projection_digest": DIGEST,
    }
    with pytest.raises(ContractValidationError, match="precedes"):
        validate_contract("evidence-reference", reference)


def test_enablement_rejects_missing_reference_artifact_mismatch_and_raw_body() -> None:
    value = json.loads((ROOT / "config/enablement-evidence.example.json").read_text())
    value["foundation"]["evidence_ids"] = ["missing"]
    with pytest.raises(ContractValidationError, match="missing evidence"):
        validate_contract("enablement-evidence", value)

    value = json.loads((ROOT / "config/enablement-evidence.example.json").read_text())
    value["evidence"][0]["digest"] = "sha256:" + "c" * 64
    with pytest.raises(ContractValidationError, match="same bytes"):
        validate_contract("enablement-evidence", value)

    value = json.loads((ROOT / "config/enablement-evidence.example.json").read_text())
    value["stdout"] = "forbidden"
    with pytest.raises(ContractValidationError, match="raw or sensitive"):
        validate_contract("enablement-evidence", value)


def test_previous_unversioned_enablement_packet_is_readable_but_not_promoted() -> None:
    legacy = {
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
    }
    normalized = normalize_enablement_evidence(legacy)
    assert normalized["schema_version"] == "vuoro.outctl.enablement-evidence/v1"
    assert normalized["authorization"]["class"] == "offline-local"
    assert normalized["foundation"]["evidence_ids"] == []
    assert normalized["identity_boundary"]["negative_rbac_tests"] is False


def test_built_wheel_contains_contract_schemas() -> None:
    wheels = sorted((ROOT / "dist").glob("outctl-*.whl"))
    if not wheels:
        pytest.skip("wheel is produced by the package gate")
    with zipfile.ZipFile(wheels[-1]) as archive:
        names = set(archive.namelist())
    assert "outctl/schemas/enablement-evidence.schema.json" in names
    assert "outctl/schemas/logical-command-request.schema.json" in names


def test_logical_request_and_runner_result_keep_status_dimensions_separate() -> None:
    bindings = {
        "action_id": 42,
        "attempt_id": "attempt-1",
        "session_id": "session-1",
        "workspace_id": "workspace-1",
        "correlation_id": "correlation-1",
    }
    request = {
        "schema_version": "vuoro.outctl.logical-command-request/v1",
        "logical_command_id": "pods",
        "command_class": "kubernetes-read",
        "logical_argv": ["get", "pods", "-A"],
        "adapter_mode": "enforce",
        "policy_ref": "k8s-v1",
        "policy_digest": DIGEST,
        "capture_required": True,
        "bindings": bindings,
        "identity": {
            "identity_source": "runner_injected",
            "executable_sha256": SHA,
            "kubeconfig_sha256": SHA,
            "context_sha256": SHA,
            "api_server_sha256": SHA,
        },
        "timeout_ms": 30_000,
    }
    validate_contract("logical-command-request", request)
    result = {
        "schema_version": "vuoro.outctl.runner-command-result/v1",
        "request_digest": DIGEST,
        "logical_command_id": "pods",
        "bindings": bindings,
        "identity_binding_sha256": SHA,
        "direct_argv": True,
        "command": {
            "started": True,
            "exit_code": 0,
            "signal": None,
            "timed_out": False,
            "cancelled": False,
        },
        "capture": {"status": "CAPTURE_FAILED", "capture_ref": None, "manifest_digest": None},
        "output_attachment": None,
        "started_at": "2026-08-09T00:00:00Z",
        "ended_at": "2026-08-09T00:00:01Z",
    }
    assert validate_contract("runner-command-result", result)["command"]["exit_code"] == 0


def test_shadow_study_ux_and_conformance_contracts_validate_metadata_only() -> None:
    outcome = {
        "exit_code": 0,
        "signal": None,
        "stdout_sha256": SHA,
        "stderr_sha256": SHA,
        "cwd_sha256": SHA,
        "duration_ms": 100,
    }
    shadow = {
        "schema_version": "vuoro.outctl.shadow-observation/v1",
        "request_digest": DIGEST,
        "direct": outcome,
        "shadow": outcome,
        "equivalence": {
            "exit_match": True,
            "signal_match": True,
            "stdout_digest_match": True,
            "stderr_digest_match": True,
            "cwd_match": True,
            "semantically_equivalent": True,
        },
        "overhead": {
            "wall_time_delta_ms": 1,
            "wall_time_regression_ppm": 10_000,
            "peak_rss_delta_bytes": 1024,
            "disk_bytes": 2048,
        },
        "recovery": {
            "forced_termination_tested": True,
            "recovered": True,
            "deadlock": False,
            "leaked_process": False,
        },
        "observed_at": "2026-08-09T00:00:00Z",
    }
    validate_contract("shadow-observation", shadow)

    protocol = json.loads((ROOT / "examples/study-protocol.json").read_text())
    analysis = json.loads((ROOT / "examples/study-analysis.json").read_text())
    validate_contract("study-protocol", protocol)
    validate_contract("study-analysis", analysis)

    ux = {
        "schema_version": "vuoro.outctl.ux-evidence/v1",
        "task_protocol_digest": DIGEST,
        "session_id_sha256": SHA,
        "turns": 3,
        "logical_commands": 4,
        "cluster_calls": 4,
        "retrievals": 2,
        "retrievals_contributing_to_findings": 1,
        "reruns_avoided": 1,
        "bypasses": [],
        "quality_preserved": True,
        "additional_critical_misses": 0,
        "evidence_references_valid": True,
        "generated_at": "2026-08-09T00:00:00Z",
    }
    validate_contract("ux-evidence", ux)

    conformance = {
        "schema_version": "vuoro.outctl.cross-harness-conformance/v1",
        "contract_digests": [DIGEST],
        "harness_a": {"id": "a", "version": "1", "adapter_commit": "a" * 40},
        "harness_b": {"id": "b", "version": "1", "adapter_commit": "b" * 40},
        "fixture_results": [{
            "fixture_id": "large",
            "bypass_equivalent": True,
            "shadow_equivalent": True,
            "enforce_envelope_equivalent": True,
            "retrieval_equivalent": True,
        }],
        "alternate_executor_constrained": True,
        "one_version_back_readable": True,
        "conformant": True,
        "generated_at": "2026-08-09T00:00:00Z",
    }
    validate_contract("cross-harness-conformance", conformance)

    shadow["equivalence"]["exit_match"] = False
    with pytest.raises(ContractValidationError, match="contradicts"):
        validate_contract("shadow-observation", shadow)

    protocol["protocol_digest"] = DIGEST
    with pytest.raises(ContractValidationError, match="canonical bytes"):
        validate_contract("study-protocol", protocol)

    analysis["paired_summary"]["protocol_valid_pairs"] = 0
    with pytest.raises(ContractValidationError, match="pair count"):
        validate_contract("study-analysis", analysis)

    ux["retrievals_contributing_to_findings"] = 3
    with pytest.raises(ContractValidationError, match="exceed"):
        validate_contract("ux-evidence", ux)

    conformance["fixture_results"][0]["retrieval_equivalent"] = False
    with pytest.raises(ContractValidationError, match="verdict"):
        validate_contract("cross-harness-conformance", conformance)
