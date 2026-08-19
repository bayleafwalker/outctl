from __future__ import annotations

from outctl.projection import ProjectionLimits
from outctl.semantic import (
    POD_HEALTH_ADAPTER,
    detect_semantic_adapter,
    project_pod_health,
)

HEADER = (
    b"NAMESPACE NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES\n"
)


def test_pod_health_projection_is_decision_complete_for_complete_table() -> None:
    rows = (
        b"media tdarr-reaper-1 0/1 OOMKilled 0 2h 10.0.0.1 node-1 <none> <none>\n"
        b"media tdarr-reaper-2 0/1 Error 0 2h 10.0.0.2 node-1 <none> <none>\n"
        b"media tdarr-worker-1 1/1 Running 0 2h 10.0.0.3 node-1 <none> <none>\n"
    )
    result = project_pod_health(
        (chunk for chunk in (HEADER[:17], HEADER[17:] + rows)),
        limits=ProjectionLimits(4096, 100, 1024),
    )

    assert result is not None
    assert result.annotations == {
        "presentation": "semantic-complete",
        "semantic_adapter": POD_HEALTH_ADAPTER,
        "scan_coverage": "complete",
        "decision_complete": True,
        "total_rows": 3,
        "status_counts": {"Error": 1, "OOMKilled": 1, "Running": 1},
        "health_predicates": {
            "Error": 1,
            "OOMKilled": 1,
            "Pending": 0,
            "CrashLoopBackOff": 0,
            "ImagePullBackOff": 0,
        },
        "anomalous_rows_total": 2,
        "anomalous_rows_shown": 2,
        "routine_rows_omitted": 1,
        "anomalous_rows_clipped": 0,
    }
    assert "Pending=0" in result.text
    assert "tdarr-reaper-1" in result.text


def test_pod_health_projection_returns_none_for_unknown_output() -> None:
    result = project_pod_health(
        [b"arbitrary command output\n"],
        limits=ProjectionLimits(1024, 20, 256),
    )
    assert result is None


def test_pod_health_projection_keeps_zero_rows_authoritative() -> None:
    result = project_pod_health(
        [b"No resources found in gatus namespace.\n"],
        limits=ProjectionLimits(1024, 20, 256),
    )
    assert result is not None
    assert result.annotations is not None
    assert result.annotations["total_rows"] == 0
    assert result.annotations["decision_complete"] is True
    assert "Pending=0" in result.text


def test_semantic_detection_requires_all_namespaces_pod_list() -> None:
    assert (
        detect_semantic_adapter(
            (
                "/usr/bin/kubectl",
                "--kubeconfig",
                "/tmp/x",
                "--context",
                "readonly",
                "get",
                "pods",
                "-A",
            )
        )
        == POD_HEALTH_ADAPTER
    )
    assert detect_semantic_adapter(("kubectl", "get", "pods")) is None
    assert detect_semantic_adapter(("kubectl", "get", "nodes", "-A")) is None
