"""Deterministic, raw-free W1 v2 comparison oracle.

The oracle compares contract projections, never command output.  Exact fields
must be equal; semantic rules compare normalized invariants; intentional
differences must be declared and must actually differ.  Any other difference
is a failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_MISSING = object()
_POLICY_FIELDS = ("snapshot_id", "ref", "digest")
_RAW_KEYS = {
    "stdout",
    "stderr",
    "stdout_bytes",
    "stderr_bytes",
    "raw_output",
    "raw_bytes",
    "projection_body",
    "local_path",
    "spool_path",
    "secret_value",
    "secret_values",
    "secret_material",
}
_SEMANTIC_RULES = {
    "command-outcome",
    "capture-completeness",
    "policy-binding",
}


class ComparisonMismatch(ValueError):
    """Raised when a fixture or cross-contract binding is invalid."""


@dataclass(frozen=True)
class ComparisonReport:
    """Machine-readable result for one matrix case."""

    case_id: str
    passed: bool
    violations: tuple[str, ...]


def _path(value: Any, dotted: str) -> Any:
    current = value
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if not isinstance(value, dict):
        return {prefix: value}
    flattened: dict[str, Any] = {}
    for key in sorted(value):
        child = f"{prefix}.{key}" if prefix else key
        flattened.update(_flatten(value[key], child))
    return flattened


def _command_outcome(value: dict[str, Any]) -> tuple[Any, ...]:
    command = value.get("command")
    if not isinstance(command, dict):
        return (_MISSING,)
    return tuple(
        command.get(key, _MISSING)
        for key in ("started", "exit_code", "signal", "timed_out", "cancelled")
    )


def _capture_completeness(value: dict[str, Any]) -> tuple[Any, ...]:
    capture = value.get("capture")
    if not isinstance(capture, dict):
        return (_MISSING,)
    status = capture.get("status", _MISSING)
    classes = {
        "complete": "complete",
        "truncated": "incomplete",
        "degraded": "incomplete",
        "recovered-incomplete": "incomplete",
        "failed": "failed",
        "bypassed": "bypassed",
        "not-requested": "not-requested",
    }
    return classes.get(status, _MISSING), capture.get("complete", _MISSING)


def _policy_triple(value: dict[str, Any]) -> tuple[Any, ...]:
    policy = value.get("policy")
    if not isinstance(policy, dict):
        return (_MISSING, _MISSING, _MISSING)
    return tuple(policy.get(field, _MISSING) for field in _POLICY_FIELDS)


def _semantic_value(rule: str, value: dict[str, Any]) -> tuple[Any, ...]:
    if rule == "command-outcome":
        return _command_outcome(value)
    if rule == "capture-completeness":
        return _capture_completeness(value)
    if rule == "policy-binding":
        return _policy_triple(value)
    raise ComparisonMismatch(f"unknown semantic rule: {rule}")


def _semantic_paths(rule: str) -> set[str]:
    if rule == "command-outcome":
        return {"command"}
    if rule == "capture-completeness":
        return {"capture.status", "capture.complete"}
    if rule == "policy-binding":
        return {"policy"}
    raise ComparisonMismatch(f"unknown semantic rule: {rule}")


def _covered(path: str, prefixes: set[str]) -> bool:
    return any(path == prefix or path.startswith(prefix + ".") for prefix in prefixes)


def compare_case(case: dict[str, Any]) -> ComparisonReport:
    """Compare one raw-free matrix case using its declared rules."""
    case_id = case.get("id")
    direct = case.get("direct")
    wrapped = case.get("wrapped")
    rules = case.get("rules")
    if (
        not isinstance(case_id, str)
        or not isinstance(direct, dict)
        or not isinstance(wrapped, dict)
    ):
        raise ComparisonMismatch("case requires string id and direct/wrapped objects")
    if not isinstance(rules, dict):
        raise ComparisonMismatch(f"{case_id}: rules must be an object")

    exact = rules.get("exact", [])
    semantic = rules.get("semantic", [])
    intentional = rules.get("intentional", [])
    if not isinstance(exact, list) or not all(isinstance(item, str) for item in exact):
        raise ComparisonMismatch(f"{case_id}: exact rules must be dotted paths")
    if not isinstance(semantic, list) or not all(item in _SEMANTIC_RULES for item in semantic):
        raise ComparisonMismatch(f"{case_id}: unknown semantic rule")
    if not isinstance(intentional, list) or not all(isinstance(item, str) for item in intentional):
        raise ComparisonMismatch(f"{case_id}: intentional rules must be dotted paths")

    violations: list[str] = []
    exact_paths = set(exact)
    intentional_paths = set(intentional)
    semantic_paths = {path for rule in semantic for path in _semantic_paths(rule)}

    for path in exact:
        if _path(direct, path) != _path(wrapped, path):
            violations.append(f"exact mismatch: {path}")

    for rule in semantic:
        if _semantic_value(rule, direct) != _semantic_value(rule, wrapped):
            violations.append(f"semantic mismatch: {rule}")

    for path in intentional:
        if _path(direct, path) == _path(wrapped, path):
            violations.append(f"intentional difference missing: {path}")

    all_paths = set(_flatten(direct)) | set(_flatten(wrapped))
    for path in sorted(all_paths):
        if _path(direct, path) == _path(wrapped, path):
            continue
        if path in exact_paths or path in intentional_paths or _covered(path, semantic_paths):
            continue
        violations.append(f"unclassified mismatch: {path}")

    return ComparisonReport(case_id, not violations, tuple(violations))


def _assert_raw_free(value: Any, location: str = "matrix") -> None:
    if isinstance(value, dict):
        forbidden = _RAW_KEYS.intersection(value)
        if forbidden:
            raise ComparisonMismatch(f"{location}: raw field(s): {sorted(forbidden)}")
        for key, child in value.items():
            _assert_raw_free(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_raw_free(child, f"{location}[{index}]")


def validate_matrix(matrix: dict[str, Any]) -> tuple[ComparisonReport, ...]:
    """Validate all expected pass/fail cases in a conformance matrix."""
    if matrix.get("schema_version") != "vuoro.outctl.comparison-matrix/v1":
        raise ComparisonMismatch("unsupported comparison matrix schema")
    cases = matrix.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ComparisonMismatch("comparison matrix requires cases")
    _assert_raw_free(matrix)
    reports: list[ComparisonReport] = []
    for case in cases:
        if not isinstance(case, dict):
            raise ComparisonMismatch("comparison matrix case must be an object")
        report = compare_case(case)
        expected = case.get("expected")
        if expected not in {"pass", "fail"}:
            raise ComparisonMismatch(f"{report.case_id}: expected must be pass or fail")
        if (expected == "pass") != report.passed:
            raise ComparisonMismatch(
                f"{report.case_id}: expected {expected}, got {report.violations}"
            )
        expected_violations = case.get("expected_violations", [])
        if not isinstance(expected_violations, list) or not all(
            isinstance(item, str) for item in expected_violations
        ):
            raise ComparisonMismatch(f"{report.case_id}: expected_violations must be strings")
        for expected_violation in expected_violations:
            if not any(expected_violation in violation for violation in report.violations):
                raise ComparisonMismatch(
                    f"{report.case_id}: missing expected violation {expected_violation}"
                )
        reports.append(report)
    return tuple(reports)


def validate_policy_binding(snapshot: dict[str, Any], document: dict[str, Any]) -> None:
    """Reject a request/result/delta whose policy triple differs from a snapshot."""
    expected = (
        snapshot.get("snapshot_id"),
        snapshot.get("policy_ref"),
        snapshot.get("policy_digest"),
    )
    observed = _policy_triple(document)
    if observed != expected:
        raise ComparisonMismatch(
            f"policy binding mismatch: expected {expected!r}, observed {observed!r}"
        )
    cache = snapshot.get("cache")
    if isinstance(cache, dict) and cache.get("snapshot_id") != snapshot.get("snapshot_id"):
        raise ComparisonMismatch("policy cache snapshot_id mismatch")
