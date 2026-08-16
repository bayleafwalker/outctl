from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from outctl.contracts import _canonical_digest
from outctl.harness import Launcher, LaunchPlanError, plan_sessions
from outctl.scenarios import ProcessFixtureProvider, ScenarioHandler
from outctl.study import compile_study_analysis


def _v3_documents(tmp_path: Path) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    fixture = {"provider": "process-fixture", "operation": "stdout_lines", "count": 3}
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text(json.dumps(fixture, sort_keys=True), encoding="utf-8")
    facts = {
        "schema_version": "vuoro.outctl.expected-facts/v1",
        "scenario_id": "stream.small",
        "facts": [
            {
                "fact_id": "ok",
                "key": "stream",
                "status": "healthy",
                "severity": "info",
                "critical": False,
            }
        ],
    }
    facts_path = tmp_path / "facts.json"
    facts_path.write_text(json.dumps(facts, sort_keys=True), encoding="utf-8")
    package = {
        "schema_version": "vuoro.outctl.scenario-package/v2",
        "scenario_id": "stream.small",
        "scenario_class": "stream.small",
        "provider": "process-fixture",
        "requires": {
            "cluster": False,
            "network": False,
            "mutation_authority": False,
            "session_budget": 1,
        },
        "seed": 1,
        "fixture_digest": "sha256:" + hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
        "expected_facts_digest": "sha256:" + hashlib.sha256(facts_path.read_bytes()).hexdigest(),
        "replayable": True,
        "mutation_authority_required": False,
    }
    package_path = tmp_path / "package.json"
    package_path.write_text(json.dumps(package, sort_keys=True), encoding="utf-8")
    suite: dict[str, object] = {
        "schema_version": "vuoro.outctl.scenario-suite/v2",
        "suite_id": "suite",
        "suite_digest": "",
        "required_classes": ["stream.small"],
        "scenarios": [
            {
                "scenario_id": "stream.small",
                "scenario_class": "stream.small",
                "package": {
                    "path": "package.json",
                    "sha256": "sha256:" + hashlib.sha256(package_path.read_bytes()).hexdigest(),
                },
                "fixture": {"path": "fixture.json", "sha256": package["fixture_digest"]},
                "expected_facts": {
                    "path": "facts.json",
                    "sha256": package["expected_facts_digest"],
                },
            }
        ],
    }
    suite["suite_digest"] = _canonical_digest(suite, omit="suite_digest")
    matrix: dict[str, object] = {
        "schema_version": "vuoro.outctl.arm-matrix/v1",
        "matrix_id": "matrix",
        "matrix_digest": "",
        "arms": [
            {"arm_id": "A", "capture": "none", "projection": "native", "tool_surface": "command"},
            {
                "arm_id": "B",
                "capture": "outctl",
                "projection": "bounded",
                "tool_surface": "command",
            },
        ],
        "contrasts": [{"contrast_id": "B_vs_A", "treatment_arm": "B", "control_arm": "A"}],
    }
    matrix["matrix_digest"] = _canonical_digest(matrix, omit="matrix_digest")
    protocol: dict[str, object] = {
        "schema_version": "vuoro.outctl.study-protocol/v3",
        "protocol_id": "protocol",
        "protocol_digest": "",
        "digest_scope": "canonical-json-v1",
        "frozen_at": "2026-08-16T00:00:00Z",
        "repository_commit": "a" * 40,
        "scenario_suite_path": "suite.json",
        "scenario_suite_digest": suite["suite_digest"],
        "arm_matrix_path": "matrix.json",
        "arm_matrix_digest": matrix["matrix_digest"],
        "arm_ids": ["A", "B"],
        "contrasts": [{"contrast_id": "B_vs_A", "treatment_arm": "B", "control_arm": "A"}],
        "runner": "test",
        "replicates": 2,
        "randomization_seed": 7,
        "limits": {"max_sessions": None, "max_concurrent_sessions": None, "max_credits": None},
        "estimated_credits_per_session": 0,
        "quality_scoring_version": "expected-fact-recall/v1",
        "noninferiority_margin_ppm": 50_000,
        "critical_severities": ["critical", "high"],
        "cache_strata": ["unknown"],
        "primary_outcomes": ["quality", "output"],
        "secondary_outcomes": [],
        "exclusion_rules": [],
        "stopping_rules": ["stop on mutation"],
    }
    protocol["protocol_digest"] = _canonical_digest(protocol, omit="protocol_digest")
    return protocol, suite, matrix


def test_plan_is_n_arm_and_rotates_start_order(tmp_path: Path) -> None:
    protocol, suite, matrix = _v3_documents(tmp_path)
    plan = plan_sessions(protocol, suite, matrix)
    assert len(plan.sessions) == 4
    assert all(len(group.sessions) == 2 for group in plan.groups)
    assert plan.groups[0].sessions[0].arm_id != plan.groups[1].sessions[0].arm_id


def test_plan_enforces_adjustable_session_and_credit_limits(tmp_path: Path) -> None:
    protocol, suite, matrix = _v3_documents(tmp_path)
    protocol["limits"] = {"max_sessions": 3, "max_concurrent_sessions": None, "max_credits": None}
    protocol["protocol_digest"] = _canonical_digest(protocol, omit="protocol_digest")
    with pytest.raises(LaunchPlanError, match="max_sessions"):
        plan_sessions(protocol, suite, matrix)

    protocol["limits"] = {"max_sessions": None, "max_concurrent_sessions": None, "max_credits": 1}
    protocol["estimated_credits_per_session"] = 1
    protocol["protocol_digest"] = _canonical_digest(protocol, omit="protocol_digest")
    with pytest.raises(LaunchPlanError, match="max_credits"):
        plan_sessions(protocol, suite, matrix)


def test_process_fixture_handler_materializes_direct_argv(tmp_path: Path) -> None:
    _protocol, suite, _matrix = _v3_documents(tmp_path)
    (tmp_path / "suite.json").write_text(json.dumps(suite), encoding="utf-8")
    (tmp_path / "matrix.json").write_text(json.dumps({}), encoding="utf-8")
    handler = ScenarioHandler((ProcessFixtureProvider(),))
    scenario = handler.resolve(suite["scenarios"][0], tmp_path)
    materialized = handler.materialize(scenario, tmp_path / "materialized")
    result = subprocess.run(materialized.argv, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert result.stdout == "line-0\nline-1\nline-2\n"
    assert materialized.environment["OUTCTL_SCENARIO_ID"] == "stream.small"


def test_launcher_resolves_and_materializes_handler_per_session(tmp_path: Path) -> None:
    _protocol, suite, matrix = _v3_documents(tmp_path)
    handler = ScenarioHandler((ProcessFixtureProvider(),))
    results = Launcher().launch_with_handler(
        _protocol,
        suite,
        matrix,
        handler,
        tmp_path,
        tmp_path / "sessions",
        lambda session, materialized: {
            "session_id": session.session_id,
            "argv": materialized.argv,
        },
    )
    assert len(results) == 4
    assert {result["session_id"].split("/")[-1] for result in results} == {"A", "B"}


def test_v3_analysis_requires_arm_keyed_sessions(tmp_path: Path) -> None:
    protocol, _suite, _matrix = _v3_documents(tmp_path)
    observations = {
        "dataset_class": "confirmatory",
        "generated_at": "2026-08-16T00:00:00Z",
        "sessions": [],
    }
    with pytest.raises(Exception, match="sessions"):
        compile_study_analysis(protocol, observations)
