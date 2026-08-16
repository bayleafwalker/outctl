"""Conservative semantic projection for one Kubernetes pod inventory shape.

This module is intentionally acceptance-harness local.  It is not a general
Kubernetes summarizer: the completeness claim is available only for the exact
unfiltered all-namespaces inventory used by the frozen workflow.  Any scoped
or filtered command must remain a generic projection so that zero counts
cannot be mistaken for cluster-wide conclusions.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


class SemanticPodError(ValueError):
    """Raised when a pod command cannot support the semantic contract."""


_POD_COMMAND = ("get", "pods", "-A", "-o", "wide")
_HEALTHY_PHASES = frozenset(("Running", "Succeeded"))
_PROBLEM_REASONS = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "ContainerStatusUnknown",
        "Evicted",
        "Unknown",
    }
)
_TABLE_SPLIT = re.compile(r"\s+")


def _command_tail(argv: Sequence[str]) -> tuple[str, ...]:
    """Return the command portion after harmless kubectl global flags.

    The adapter accepts only a small, explicit global-flag vocabulary.  In
    particular, selectors, namespace flags, jsonpath, and arbitrary output
    formats are never silently normalized into a complete scan.
    """

    if not argv or argv[0].rsplit("/", 1)[-1] != "kubectl":
        raise SemanticPodError("semantic pod projection requires kubectl")
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in {"--kubeconfig", "--context", "--server"}:
            if index + 1 >= len(argv):
                raise SemanticPodError(f"{token} requires a value")
            index += 2
            continue
        if token.startswith("--kubeconfig=") or token.startswith("--context="):
            index += 1
            continue
        break
    return tuple(argv[index:])


def is_exact_unfiltered_inventory(argv: Sequence[str]) -> bool:
    """Return whether ``argv`` is the only command with complete-scan scope."""

    try:
        return _command_tail(argv) == _POD_COMMAND
    except SemanticPodError:
        return False


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _row_from_json(item: Mapping[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
    status = item.get("status") if isinstance(item.get("status"), Mapping) else {}
    containers = status.get("containerStatuses")
    container_statuses = containers if isinstance(containers, list) else []
    ready_values = [
        value.get("ready")
        for value in container_statuses
        if isinstance(value, Mapping) and isinstance(value.get("ready"), bool)
    ]
    waiting_reasons = [
        waiting.get("reason")
        for value in container_statuses
        if isinstance(value, Mapping)
        for waiting in [value.get("state", {}).get("waiting")]
        if isinstance(waiting, Mapping) and isinstance(waiting.get("reason"), str)
    ]
    restarts = sum(
        value.get("restartCount", 0)
        for value in container_statuses
        if isinstance(value, Mapping) and isinstance(value.get("restartCount", 0), int)
    )
    phase_value = status.get("phase")
    if not isinstance(phase_value, str):
        # Offline replay fixtures use a deliberately normalized row shape.
        phase_value = item.get("phase")
    phase = phase_value if isinstance(phase_value, str) else "Unknown"
    normalized_name = item.get("name")
    normalized_ready = item.get("ready")
    normalized_waiting = item.get("waiting")
    return {
        "namespace": (
            metadata.get("namespace")
            if isinstance(metadata.get("namespace"), str)
            else item.get("namespace")
            if isinstance(item.get("namespace"), str)
            else "?"
        ),
        "name": (
            metadata.get("name")
            if isinstance(metadata.get("name"), str)
            else normalized_name
            if isinstance(normalized_name, str)
            else "?"
        ),
        "phase": phase,
        "ready": all(ready_values) if ready_values else _bool(normalized_ready),
        "waiting_reasons": sorted(
            set(waiting_reasons)
            | ({normalized_waiting} if isinstance(normalized_waiting, str) else set())
        ),
        "restart_count": (
            item.get("restart_count")
            if isinstance(item.get("restart_count"), int)
            else restarts
        ),
        "terminating": isinstance(metadata.get("deletionTimestamp"), str),
    }


def _rows_from_text(text: str) -> list[dict[str, Any]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header = _TABLE_SPLIT.split(lines[0])
    expected = {"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE"}
    if not expected.issubset(header):
        raise SemanticPodError("pod output is not the canonical wide table")
    positions = {name: header.index(name) for name in expected}
    rows: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = _TABLE_SPLIT.split(line)
        if len(fields) <= max(positions.values()):
            raise SemanticPodError("pod table row is incomplete")
        ready_text = fields[positions["READY"]]
        ready_match = re.fullmatch(r"(\d+)/(\d+)", ready_text)
        ready = None if ready_match is None else ready_match.group(1) == ready_match.group(2)
        try:
            restarts = int(fields[positions["RESTARTS"]].split("(")[0])
        except ValueError:
            restarts = 0
        rows.append(
            {
                "namespace": fields[positions["NAMESPACE"]],
                "name": fields[positions["NAME"]],
                "phase": fields[positions["STATUS"]],
                "ready": ready,
                "waiting_reasons": [],
                "restart_count": restarts,
                "terminating": False,
            }
        )
    return rows


def _rows(output: str) -> list[dict[str, Any]]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        return _rows_from_text(output)
    if not isinstance(value, Mapping) or not isinstance(value.get("items"), list):
        raise SemanticPodError("pod JSON output lacks an items array")
    return [
        _row_from_json(item)
        for item in value["items"]
        if isinstance(item, Mapping)
    ]


def project_pod_inventory(argv: Sequence[str], output: str) -> str:
    """Project a complete, unfiltered pod inventory with scoped conclusions."""

    if not is_exact_unfiltered_inventory(argv):
        raise SemanticPodError(
            "semantic completeness is restricted to: kubectl get pods -A -o wide"
        )
    rows = _rows(output)
    anomalies: list[dict[str, Any]] = []
    for row in rows:
        reasons = set(row["waiting_reasons"])
        phase = row["phase"]
        if (
            phase not in _HEALTHY_PHASES
            or reasons & _PROBLEM_REASONS
            or row["ready"] is False
            or row["terminating"]
            or row["restart_count"] > 0
        ):
            anomalies.append(
                {
                    "namespace": row["namespace"],
                    "name": row["name"],
                    "phase": phase,
                    "ready": row["ready"],
                    "waiting_reasons": sorted(reasons),
                    "restart_count": row["restart_count"],
                    "terminating": row["terminating"],
                }
            )
    payload = {
        "semantic_projection": "kubernetes-pod-inventory/v1",
        "population": {"resource": "pods", "namespaces": "all"},
        "selection_scope": {
            "field_selector": None,
            "label_selector": None,
            "namespace": None,
            "conclusions_apply_to": "all_rows_returned_by_exact_command",
        },
        "coverage": {
            "source_rows_scanned": "complete",
            "completeness_basis": "exact_unfiltered_all_namespaces_inventory",
        },
        "rows_scanned": len(rows),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "rows_not_matching_declared_predicates": len(rows) - len(anomalies),
    }
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
