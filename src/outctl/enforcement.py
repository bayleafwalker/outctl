"""Fail-closed command-class selection and enforcement evidence compilation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from outctl.contracts import ContractValidationError, validate_contract


class EnforcementError(ValueError):
    """Raised when enforcement policy or observations are inconsistent."""


def select_command_mode(policy: Mapping[str, Any], command_class: str) -> dict[str, Any]:
    """Select enforcement only for one uniquely approved command class."""
    validate_contract("approved-command-policy", policy)
    matches = [
        item for item in policy["approved_classes"] if item.get("command_class") == command_class
    ]
    if len(matches) > 1:
        raise EnforcementError(f"command class is approved more than once: {command_class}")
    if not matches:
        return {
            "command_class": command_class,
            "mode": "bypass",
            "reason": "command-class-not-approved",
            "policy_digest": policy["policy_digest"],
        }
    selected = matches[0]
    return {
        "command_class": command_class,
        "mode": "enforce",
        "reason": "approved-output-class",
        "policy_digest": policy["policy_digest"],
        "max_full_output_bytes": selected["max_full_output_bytes"],
        "minimum_oversized_reduction_ppm": selected["minimum_oversized_reduction_ppm"],
    }


def compile_enforcement_observation(
    policy: Mapping[str, Any], observation: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind measured enforcement results to the approved selector policy."""
    selection = select_command_mode(policy, str(observation.get("command_class", "")))
    if observation.get("policy_digest") != selection["policy_digest"]:
        raise EnforcementError("enforcement observation policy digest mismatch")
    if observation.get("selected_mode") != selection["mode"]:
        raise EnforcementError("observed mode contradicts approved command selector")
    raw_bytes = observation.get("raw_bytes")
    exposed_bytes = observation.get("exposed_bytes")
    if not isinstance(raw_bytes, int) or isinstance(raw_bytes, bool) or raw_bytes < 0:
        raise EnforcementError("raw_bytes must be a non-negative integer")
    if not isinstance(exposed_bytes, int) or isinstance(exposed_bytes, bool) or exposed_bytes < 0:
        raise EnforcementError("exposed_bytes must be a non-negative integer")
    reduction = round((raw_bytes - exposed_bytes) * 1_000_000 / raw_bytes) if raw_bytes else None
    oversized = selection["mode"] == "enforce" and raw_bytes > int(
        selection["max_full_output_bytes"]
    )
    minimum = int(selection.get("minimum_oversized_reduction_ppm", 500_000))
    bypass_count = observation.get("bypass_count")
    if not isinstance(bypass_count, int) or isinstance(bypass_count, bool) or bypass_count < 0:
        raise EnforcementError("bypass_count must be a non-negative integer")
    accepted = (
        selection["mode"] == "enforce"
        and (not oversized or (reduction is not None and reduction >= minimum))
        and observation.get("quality_preserved") is True
        and observation.get("redaction_verified") is True
        and observation.get("retrieval_verified") is True
        and observation.get("rollback_verified") is True
        and bypass_count == 0
    )
    result = {
        "schema_version": "vuoro.outctl.enforcement-observation/v1",
        "policy_digest": selection["policy_digest"],
        "command_class": selection["command_class"],
        "selected_mode": selection["mode"],
        "oversized": oversized,
        "raw_bytes": raw_bytes,
        "exposed_bytes": exposed_bytes,
        "reduction_ppm": reduction,
        "quality_preserved": observation.get("quality_preserved") is True,
        "redaction_verified": observation.get("redaction_verified") is True,
        "retrieval_verified": observation.get("retrieval_verified") is True,
        "rollback_verified": observation.get("rollback_verified") is True,
        "bypass_count": bypass_count,
        "accepted": accepted,
        "observed_at": observation.get("observed_at"),
    }
    try:
        return validate_contract("enforcement-observation", result)
    except ContractValidationError as exc:
        raise EnforcementError(str(exc)) from exc
