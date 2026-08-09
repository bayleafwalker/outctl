from __future__ import annotations

from copy import deepcopy

import pytest

from outctl.contracts import _canonical_digest
from outctl.enforcement import (
    EnforcementError,
    compile_enforcement_observation,
    select_command_mode,
)


def _policy() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "vuoro.outctl.approved-command-policy/v1",
        "policy_id": "selected-v1",
        "policy_digest": "",
        "approved_classes": [
            {
                "command_class": "kubernetes-pod-inventory",
                "max_full_output_bytes": 4096,
                "minimum_oversized_reduction_ppm": 500_000,
            }
        ],
    }
    value["policy_digest"] = _canonical_digest(value, omit="policy_digest")
    return value


def _observation(policy: dict[str, object]) -> dict[str, object]:
    return {
        "policy_digest": policy["policy_digest"],
        "command_class": "kubernetes-pod-inventory",
        "selected_mode": "enforce",
        "raw_bytes": 10_000,
        "exposed_bytes": 2_000,
        "quality_preserved": True,
        "redaction_verified": True,
        "retrieval_verified": True,
        "rollback_verified": True,
        "bypass_count": 0,
        "observed_at": "2026-08-09T03:00:00Z",
    }


def test_selector_bypasses_unknown_and_enforces_approved_class() -> None:
    policy = _policy()
    assert select_command_mode(policy, "small-status")["mode"] == "bypass"
    assert select_command_mode(policy, "kubernetes-pod-inventory")["mode"] == "enforce"


def test_enforcement_observation_applies_oversized_quality_gates() -> None:
    policy = _policy()
    result = compile_enforcement_observation(policy, _observation(policy))
    assert result["oversized"] is True
    assert result["reduction_ppm"] == 800_000
    assert result["accepted"] is True


def test_enforcement_observation_fails_closed_on_policy_or_mode_drift() -> None:
    policy = _policy()
    observation = deepcopy(_observation(policy))
    observation["selected_mode"] = "bypass"
    with pytest.raises(EnforcementError, match="contradicts"):
        compile_enforcement_observation(policy, observation)


def test_enforcement_rejects_insufficient_oversized_reduction() -> None:
    policy = _policy()
    observation = _observation(policy)
    observation["exposed_bytes"] = 6_000
    result = compile_enforcement_observation(policy, observation)
    assert result["accepted"] is False
