from __future__ import annotations

import hashlib
import json
from pathlib import Path

from outctl.contracts import validate_contract

ROOT = Path(__file__).parents[1]
STUDY = ROOT / "studies/controlled-v1"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_seeded_suite_binds_replayable_fixtures_and_fact_denominators() -> None:
    suite = validate_contract("study-suite", _load(STUDY / "suite.json"))
    assert len(suite["scenarios"]) == 6
    for binding in suite["scenarios"]:
        manifest_path = ROOT / binding["manifest"]["path"]
        facts_path = ROOT / binding["expected_facts"]["path"]
        manifest = validate_contract("scenario-manifest", _load(manifest_path))
        facts = validate_contract("expected-facts", _load(facts_path))
        fixture_path = STUDY / "fixtures" / f"{binding['scenario_class']}.json"
        assert binding["manifest"]["sha256"] == _digest(manifest_path)
        assert binding["expected_facts"]["sha256"] == _digest(facts_path)
        assert manifest["fixture_digest"] == _digest(fixture_path)
        assert manifest["expected_facts_digest"] == _digest(facts_path)
        assert manifest["replayable"] is True
        assert manifest["mutation_authority_required"] is False
        assert facts["scenario_id"] == binding["scenario_id"]
        assert facts["facts"]
