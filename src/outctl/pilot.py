"""Validation for raw-free qualitative workstation pilot reports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class PilotReportError(ValueError):
    """Raised when a pilot report is incomplete or risks carrying raw output."""


@dataclass(frozen=True)
class PilotReportSummary:
    harness: str
    command_class: str
    policy_digest: str
    baseline_exposed_tokens: int
    enforce_exposed_tokens: int
    retrieval_count: int


_BANNED_KEY_PARTS = ("raw_output", "stdout", "stderr", "projection_text", "inline_text")


def _require_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PilotReportError(f"{name} must be a non-empty string")
    return value


def _require_non_negative_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PilotReportError(f"{name} must be a non-negative integer")
    return value


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PilotReportError(f"{name} must be an object")
    return value


def _reject_raw_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise PilotReportError("report keys must be strings")
            if any(part in key.casefold() for part in _BANNED_KEY_PARTS):
                raise PilotReportError(f"raw/model body field is forbidden: {key}")
            _reject_raw_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_raw_fields(nested)


def validate_pilot_report(report: Mapping[str, Any]) -> PilotReportSummary:
    """Validate required qualitative pilot evidence without retaining raw bodies."""
    _reject_raw_fields(report)
    pilot = _mapping(report.get("pilot"), "pilot")
    harness = _require_string(pilot.get("harness"), "pilot.harness").casefold()
    if harness not in {"codex", "claude"}:
        raise PilotReportError("pilot.harness must be codex or claude")
    command_class = _require_string(pilot.get("command_class"), "pilot.command_class")
    if command_class != "appservice-health-check":
        raise PilotReportError("pilot.command_class must be appservice-health-check")
    policy_digest = _require_string(pilot.get("policy_digest"), "pilot.policy_digest")

    baseline = _mapping(report.get("baseline"), "baseline")
    enforce = _mapping(report.get("enforce"), "enforce")
    baseline_tokens = _require_non_negative_int(
        baseline.get("exposed_tokens"), "baseline.exposed_tokens"
    )
    enforce_tokens = _require_non_negative_int(
        enforce.get("exposed_tokens"), "enforce.exposed_tokens"
    )
    _require_non_negative_int(enforce.get("raw_tokens"), "enforce.raw_tokens")
    _require_non_negative_int(enforce.get("retrieved_tokens"), "enforce.retrieved_tokens")
    retrieval_count = _require_non_negative_int(
        enforce.get("retrieval_count"), "enforce.retrieval_count"
    )
    _require_non_negative_int(enforce.get("wall_time_ms"), "enforce.wall_time_ms")
    _require_non_negative_int(enforce.get("wrapper_overhead_ms"), "enforce.wrapper_overhead_ms")

    assessment = _mapping(report.get("assessment"), "assessment")
    _require_string(
        assessment.get("harness_native_context_management"),
        "assessment.harness_native_context_management",
    )
    _require_string(assessment.get("outctl_increment"), "assessment.outctl_increment")
    _require_string(assessment.get("recommendation"), "assessment.recommendation")
    return PilotReportSummary(
        harness=harness,
        command_class=command_class,
        policy_digest=policy_digest,
        baseline_exposed_tokens=baseline_tokens,
        enforce_exposed_tokens=enforce_tokens,
        retrieval_count=retrieval_count,
    )
