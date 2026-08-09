from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from outctl.contracts import (
    ContractValidationError,
    validate_controlled_study_launch,
)

CLASSES = (
    "healthy",
    "node-not-ready",
    "crashloop",
    "gitops-reconciliation-failure",
    "storage-failure",
    "warning-events",
)
HEAD = "1" * 40


def _canonical(value: dict[str, object], omitted: str) -> str:
    body = {key: item for key, item in value.items() if key != omitted}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _write(path: Path, value: dict[str, object]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _make_study(root: Path) -> Path:
    (root / ".git").mkdir()
    (root / ".git/HEAD").write_text(HEAD + "\n", encoding="ascii")
    bindings = []
    for index, scenario_class in enumerate(CLASSES):
        scenario_id = f"scenario-{index}"
        facts_path = root / f"studies/{scenario_id}/facts.json"
        facts_digest = _write(facts_path, {
            "schema_version": "vuoro.outctl.expected-facts/v1",
            "scenario_id": scenario_id,
            "facts": [{"fact_id": "fact", "key": "cluster", "status": scenario_class,
                       "severity": "info", "critical": False}],
        })
        manifest_path = root / f"studies/{scenario_id}/manifest.json"
        manifest_digest = _write(manifest_path, {
            "schema_version": "vuoro.outctl.scenario-manifest/v1",
            "scenario_id": scenario_id,
            "scenario_class": scenario_class,
            "seed": index,
            "fixture_digest": "sha256:" + hashlib.sha256(scenario_id.encode()).hexdigest(),
            "expected_facts_digest": facts_digest,
            "replayable": True,
            "mutation_authority_required": False,
        })
        bindings.append({
            "scenario_id": scenario_id,
            "scenario_class": scenario_class,
            "manifest": {"path": str(manifest_path.relative_to(root)), "sha256": manifest_digest},
            "expected_facts": {"path": str(facts_path.relative_to(root)), "sha256": facts_digest},
        })
    suite: dict[str, object] = {
        "schema_version": "vuoro.outctl.study-suite/v1",
        "suite_id": "suite",
        "suite_digest": "",
        "scenarios": bindings,
    }
    suite["suite_digest"] = _canonical(suite, "suite_digest")
    _write(root / "studies/suite.json", suite)
    protocol: dict[str, object] = {
        "schema_version": "vuoro.outctl.study-protocol/v2", "protocol_id": "protocol",
        "protocol_digest": "", "frozen_at": "2026-08-09T00:00:00Z",
        "repository_commit": HEAD, "study_suite_path": "studies/suite.json",
        "study_suite_digest": suite["suite_digest"],
        "quality_scoring_version": "expected-fact-recall/v1",
        "noninferiority_margin_ppm": 50000, "critical_severities": ["critical", "high"],
        "variance_pilot_pairs": 6, "confirmatory_pairs": 18, "randomization_seed": 1,
        "cache_strata": ["unknown"],
        "primary_outcomes": ["diagnostic_quality_noninferiority", "additional_critical_misses",
                             "model_visible_command_output_bytes", "uncached_read_input_tokens"],
        "secondary_outcomes": [], "exclusion_rules": [], "stopping_rules": ["stop on mutation"],
    }
    protocol["protocol_digest"] = _canonical(protocol, "protocol_digest")
    path = root / "studies/protocol.json"
    _write(path, protocol)
    return path


def _rewrite_suite_and_protocol(root: Path, suite: dict[str, object]) -> None:
    suite["suite_digest"] = _canonical(suite, "suite_digest")
    _write(root / "studies/suite.json", suite)
    protocol = json.loads((root / "studies/protocol.json").read_text())
    protocol["study_suite_digest"] = suite["suite_digest"]
    protocol["protocol_digest"] = _canonical(protocol, "protocol_digest")
    _write(root / "studies/protocol.json", protocol)


def test_valid_launch_and_one_byte_mismatch(tmp_path: Path) -> None:
    protocol = _make_study(tmp_path)
    validate_controlled_study_launch(tmp_path, protocol, "scenario-0")
    facts = tmp_path / "studies/scenario-0/facts.json"
    facts.write_bytes(facts.read_bytes() + b" ")
    with pytest.raises(ContractValidationError, match="digest mismatch"):
        validate_controlled_study_launch(tmp_path, protocol, "scenario-0")


def test_head_mismatch_fails(tmp_path: Path) -> None:
    protocol = _make_study(tmp_path)
    value = json.loads(protocol.read_text())
    value["repository_commit"] = "2" * 40
    value["protocol_digest"] = _canonical(value, "protocol_digest")
    _write(protocol, value)
    with pytest.raises(ContractValidationError, match="HEAD"):
        validate_controlled_study_launch(tmp_path, protocol, "scenario-0")


@pytest.mark.parametrize("failure", ["example", "duplicate"])
def test_example_path_and_duplicate_class_fail(tmp_path: Path, failure: str) -> None:
    protocol = _make_study(tmp_path)
    suite = json.loads((tmp_path / "studies/suite.json").read_text())
    if failure == "example":
        suite["scenarios"][0]["manifest"]["path"] = "examples/manifest.json"
    else:
        suite["scenarios"][0]["scenario_class"] = suite["scenarios"][1]["scenario_class"]
    _rewrite_suite_and_protocol(tmp_path, suite)
    with pytest.raises(ContractValidationError):
        validate_controlled_study_launch(tmp_path, protocol, "scenario-0")


@pytest.mark.parametrize("failure", ["placeholder", "mutation"])
def test_placeholder_and_unauthorized_mutation_fail(tmp_path: Path, failure: str) -> None:
    protocol = _make_study(tmp_path)
    manifest_path = tmp_path / "studies/scenario-0/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if failure == "placeholder":
        manifest["fixture_digest"] = "sha256:" + "0" * 64
    else:
        manifest["mutation_authority_required"] = True
    digest = _write(manifest_path, manifest)
    suite = json.loads((tmp_path / "studies/suite.json").read_text())
    suite["scenarios"][0]["manifest"]["sha256"] = digest
    _rewrite_suite_and_protocol(tmp_path, suite)
    with pytest.raises(ContractValidationError, match="placeholder|mutation authority"):
        validate_controlled_study_launch(tmp_path, protocol, "scenario-0")
