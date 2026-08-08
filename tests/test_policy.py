from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from outctl import (
    PolicyCycleError,
    PolicyError,
    PolicyNotFoundError,
    PolicyValidationError,
    load_policy_set,
    policy_digest,
    resolve_and_digest,
    resolve_policy,
)
from outctl.serialization import canonical_sha256

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "config/output-policies.example.yaml"


def test_load_example_policy_set() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    assert policy_set.metadata.name == "vuoro-default-output-policies"
    assert "interactive-default-v1" in policy_set.spec.policies
    assert any(profile.name == "tests" for profile in policy_set.spec.profiles)


def test_resolve_interactive_default_policy() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    policy = resolve_policy(policy_set, "interactive-default-v1")
    assert policy.metadata.name == "interactive-default-v1"
    assert policy.spec.capture.backend == "local"
    assert policy.spec.budget.estimator == "utf8-bytes-div-4-v1"
    assert policy.spec.projection.mode == "auto"
    assert policy.spec.redaction.beforeModel is True


def test_resolve_failure_diagnostics_inherits_and_overrides() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    policy = resolve_policy(policy_set, "failure-diagnostics-v1")
    assert policy.metadata.name == "failure-diagnostics-v1"
    # Inherited from interactive-default-v1
    assert policy.spec.capture.backend == "local"
    assert policy.spec.capture.maxBytes == 268435456
    assert policy.spec.redaction.beforeModel is True
    # Overridden
    assert policy.spec.budget.maxEstimatedTokens == 8000
    assert policy.spec.budget.maxBytes == 49152
    assert policy.spec.projection.mode == "failure"
    assert policy.spec.projection.failureContextAfter == 50


def test_resolve_audited_required_inherits_through_chain() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    policy = resolve_policy(policy_set, "audited-required-v1")
    assert policy.spec.capture.required is True
    assert policy.spec.capture.onFailure == "cancel-and-fail"
    assert policy.spec.capture.onQuotaExceeded == "cancel-and-fail"
    # Inherited through failure-diagnostics-v1 -> interactive-default-v1
    assert policy.spec.budget.estimator == "utf8-bytes-div-4-v1"
    # Own override
    assert policy.spec.redaction.beforeReplica is True


def test_policy_digest_is_stable() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    policy1, digest1 = resolve_and_digest(policy_set, "interactive-default-v1")
    policy2, digest2 = resolve_and_digest(policy_set, "interactive-default-v1")
    assert digest1 == digest2
    assert digest1.startswith("sha256:")
    assert len(digest1) == 7 + 64
    # Re-serializing the same model yields the same digest
    assert policy_digest(policy1) == digest1
    assert policy_digest(policy2) == digest2


def test_policy_digest_changes_when_content_changes() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    original = resolve_policy(policy_set, "interactive-default-v1")
    original_digest = policy_digest(original)

    modified_data = copy.deepcopy(original.to_dict())
    modified_data["spec"]["budget"]["maxBytes"] = 99999
    modified = __import__("outctl").OutputPolicy.from_dict(modified_data)
    modified_digest = policy_digest(modified)

    assert modified_digest != original_digest


def test_unknown_policy_fails_closed() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    with pytest.raises(PolicyNotFoundError):
        resolve_policy(policy_set, "does-not-exist")


def test_policy_cycle_fails_closed() -> None:
    data = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicySet",
        "metadata": {"name": "cycle-test"},
        "spec": {
            "defaults": {"policy": "a"},
            "policies": {
                "a": {"extends": "b"},
                "b": {"extends": "a"},
            },
            "profiles": [],
        },
    }
    policy_set = __import__("outctl").OutputPolicySet.from_dict(data)
    with pytest.raises(PolicyCycleError):
        resolve_policy(policy_set, "a")


def test_equivalent_yaml_spellings_produce_same_digest(tmp_path: Path) -> None:
    """A policy loaded from two YAML spellings with the same content must digest identically."""
    base = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicySet",
        "metadata": {"name": "spelling-test"},
        "spec": {
            "defaults": {"policy": "p"},
            "policies": {
                "p": {
                    "capture": {
                        "required": False,
                        "backend": "local",
                        "maxBytes": 1024,
                        "onFailure": "warn",
                        "onQuotaExceeded": "continue-truncated",
                    },
                    "budget": {
                        "maxEstimatedTokens": 100,
                        "maxBytes": 1024,
                        "maxLines": 100,
                        "estimator": "utf8-bytes-div-4-v1",
                    },
                    "projection": {"mode": "auto"},
                    "redaction": {
                        "beforeModel": True,
                        "beforeLocalRaw": False,
                        "beforeReplica": True,
                    },
                }
            },
            "profiles": [],
        },
    }
    path1 = tmp_path / "one.yaml"
    path2 = tmp_path / "two.yaml"
    # Different key order
    yaml.dump(base, path1.open("w"), sort_keys=True)
    yaml.dump(base, path2.open("w"), sort_keys=False)

    digest1 = resolve_and_digest(load_policy_set(path1), "p")[1]
    digest2 = resolve_and_digest(load_policy_set(path2), "p")[1]
    assert digest1 == digest2


def test_canonical_sha256_of_resolved_policy_matches_policy_digest() -> None:
    policy_set = load_policy_set(POLICY_PATH)
    policy = resolve_policy(policy_set, "interactive-default-v1")
    data = policy.to_dict()
    assert policy_digest(policy) == "sha256:" + canonical_sha256(data)


def _minimal_valid_policy_set_dict() -> dict:
    return {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicySet",
        "metadata": {"name": "validation-test"},
        "spec": {
            "defaults": {"policy": "p"},
            "policies": {"p": {"capture": {"required": False}}},
            "profiles": [],
        },
    }


def _write_policy_set(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "policy-set.yaml"
    yaml.dump(data, path.open("w"), sort_keys=False)
    return path


def test_unknown_api_version_fails_closed(tmp_path: Path) -> None:
    data = _minimal_valid_policy_set_dict()
    data["apiVersion"] = "vuoro.outctl/v999"
    path = _write_policy_set(tmp_path, data)
    with pytest.raises(PolicyValidationError):
        load_policy_set(path)


def test_wrong_kind_fails_closed(tmp_path: Path) -> None:
    data = _minimal_valid_policy_set_dict()
    data["kind"] = "OutputPolicy"
    path = _write_policy_set(tmp_path, data)
    with pytest.raises(PolicyValidationError):
        load_policy_set(path)


def test_structurally_invalid_policy_combination_fails_closed(tmp_path: Path) -> None:
    """A profile missing its required ``policy`` field is a structural violation."""
    data = _minimal_valid_policy_set_dict()
    data["spec"]["profiles"] = [{"name": "missing-policy"}]
    path = _write_policy_set(tmp_path, data)
    with pytest.raises(PolicyValidationError):
        load_policy_set(path)


def test_validation_error_is_a_policy_error(tmp_path: Path) -> None:
    data = _minimal_valid_policy_set_dict()
    data["apiVersion"] = "vuoro.outctl/v999"
    path = _write_policy_set(tmp_path, data)
    with pytest.raises(PolicyError):
        load_policy_set(path)
