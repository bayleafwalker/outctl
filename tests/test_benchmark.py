from __future__ import annotations

from pathlib import Path

from outctl.benchmark import benchmark, rollback_check


def test_model_free_benchmark_exercises_capture_retrieval_and_redaction(tmp_path: Path) -> None:
    report = benchmark(tmp_path / "spool", repetitions=1, scale=200, max_projection_bytes=512)

    assert report["passed"] is True
    assert report["summary"]["case_runs"] == 4  # type: ignore[index]
    records = report["records"]
    failure = next(record for record in records if record["case"] == "failure-in-noise")  # type: ignore[union-attr]
    secret = next(record for record in records if record["case"] == "registered-secret")  # type: ignore[union-attr]
    assert failure["command_exit"] == 7
    assert failure["marker_retrieved_without_rerun"] is True
    assert secret["secret_absent_from_projection"] is True


def test_rollback_check_forces_bypass_without_capture() -> None:
    assert rollback_check() == {
        "schema_version": "outctl.rollback-check/v1",
        "mode": "bypass",
        "command_exit": 0,
        "capture_count": 0,
        "passed": True,
    }
