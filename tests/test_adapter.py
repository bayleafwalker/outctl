from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import pytest

from outctl.adapter import (
    AdapterIdentity,
    AdapterMode,
    AdapterRequest,
    RetrievalStatus,
    resolve_adapter_mode,
    retrieve_adapter_slice,
    run_adapter,
)
from outctl.projection import ProjectionLimits


def run(request: AdapterRequest):
    return asyncio.run(run_adapter(request))


@dataclass(frozen=True)
class PilotMeasurement:
    """Numeric, output-safe evidence from one deterministic adapter run."""

    raw_bytes: int
    exposed_bytes: int
    estimated_tokens: int
    retrieval_count: int
    wall_time_ms: float
    wrapper_overhead_ms: float


def run_local_pilot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Measure bypass, shadow, and enforce without retrieving captured output."""
    stdout = b"pilot line\n" * 32
    stderr = b"pilot diagnostic\n" * 8
    expected_raw_bytes = len(stdout) + len(stderr)
    code = (
        "import sys; "
        f"sys.stdout.buffer.write({stdout!r}); "
        f"sys.stderr.buffer.write({stderr!r})"
    )
    retrieval_count = 0

    def retrieval_called(*args: object, **kwargs: object) -> object:
        nonlocal retrieval_count
        retrieval_count += 1
        raise AssertionError("adapter pilot must not retrieve captured output")

    import outctl.retrieval as retrieval

    for name in (
        "inspect_capture",
        "slice_stream",
        "tail_stream",
        "search_stream",
        "verify_capture",
    ):
        monkeypatch.setattr(retrieval, name, retrieval_called)

    measurements: dict[AdapterMode, PilotMeasurement] = {}
    for mode in AdapterMode:
        before = time.perf_counter_ns()
        result = run(
            request(
                mode,
                tmp_path / mode.value,
                code,
                projection_limits=ProjectionLimits(64, 4, 16),
            )
        )
        wall_time_ms = (time.perf_counter_ns() - before) / 1_000_000
        if mode is AdapterMode.BYPASS:
            measurements[mode] = PilotMeasurement(
                raw_bytes=expected_raw_bytes,
                exposed_bytes=expected_raw_bytes,
                estimated_tokens=(expected_raw_bytes + 3) // 4,
                retrieval_count=retrieval_count,
                wall_time_ms=wall_time_ms,
                wrapper_overhead_ms=0.0,
            )
            continue

        assert result.capture is not None
        assert result.envelope is not None
        measurements[mode] = PilotMeasurement(
            raw_bytes=result.capture.stdout_bytes + result.capture.stderr_bytes,
            exposed_bytes=result.envelope.projection.bytes,
            estimated_tokens=result.envelope.projection.estimated_tokens,
            retrieval_count=retrieval_count,
            wall_time_ms=wall_time_ms,
            wrapper_overhead_ms=0.0,
        )

    baseline = measurements[AdapterMode.BYPASS].wall_time_ms
    report = {
        mode.value: asdict(
            PilotMeasurement(
                **{
                    **asdict(measurement),
                    "wrapper_overhead_ms": measurement.wall_time_ms - baseline,
                }
            )
        )
        for mode, measurement in measurements.items()
    }
    return {
        **report,
        # This is deliberately a qualitative pilot note, not a release
        # threshold.  It records authority boundaries alongside the metrics.
        "qualitative_assessment": {
            "harness_managed": "direct command execution and ordinary command outcome",
            "outctl_adds": "bounded projection, local capture metrics, and no-rerun retrieval",
        },
    }


def request(mode: AdapterMode, tmp_path: Path, code: str, **kwargs: object) -> AdapterRequest:
    return AdapterRequest(
        mode=mode,
        argv=(sys.executable, "-c", code),
        policy_ref="pilot",
        policy_digest="sha256:" + "1" * 64,
        identity=AdapterIdentity(host_id="test-host", harness="pytest"),
        spool_root=tmp_path / "spool",
        **kwargs,
    )


def test_bypass_executes_directly_without_creating_capture_root(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    result = run(
        request(
            AdapterMode.BYPASS,
            tmp_path,
            "from pathlib import Path; Path('ran').write_text('yes')",
            cwd=tmp_path,
        )
    )

    assert result.command.exit_code == 0
    assert marker.read_text() == "yes"
    assert result.capture is result.envelope is result.receipt is None
    assert not (tmp_path / "spool").exists()


def test_mode_resolution_supports_config_and_documented_environment_flags() -> None:
    assert AdapterMode.from_environment({}) is AdapterMode.BYPASS
    assert AdapterMode.from_environment({"OUTCTL_MODE": "shadow"}) is AdapterMode.SHADOW
    assert resolve_adapter_mode(AdapterMode.ENFORCE, environ={}) is AdapterMode.ENFORCE
    assert resolve_adapter_mode("enforce", environ={"OUTCTL_MODE": "shadow"}) is AdapterMode.ENFORCE
    assert (
        resolve_adapter_mode(AdapterMode.ENFORCE, environ={"OUTCTL_ENABLED": "0"})
        is AdapterMode.BYPASS
    )
    with pytest.raises(ValueError, match="OUTCTL_MODE"):
        AdapterMode.from_environment({"OUTCTL_MODE": "unknown"})


def test_shadow_returns_command_outcome_and_observation(tmp_path: Path) -> None:
    result = run(request(AdapterMode.SHADOW, tmp_path, "print('observed'); raise SystemExit(7)"))

    assert result.command.exit_code == 7
    assert result.ordinary_result is result.command
    assert result.capture is not None
    assert result.capture.capture_status == "COMPLETE"
    assert result.envelope is not None
    assert result.envelope.command.exit_code == 7
    assert result.envelope.projection.inline_text == "observed\n"
    assert result.receipt is not None
    assert result.receipt["mode"] == "shadow"


def test_enforce_envelope_exposes_only_opaque_capture_location(tmp_path: Path) -> None:
    result = run(request(AdapterMode.ENFORCE, tmp_path, "print('bounded')"))

    assert result.envelope is not None
    serialized = json.dumps(result.envelope.to_dict(), sort_keys=True)
    assert result.envelope.capture.source.path == (
        f"outctl://capture/{result.envelope.capture_id}"
    )
    assert str(tmp_path.resolve()) not in serialized
    assert "stdout.raw" not in serialized
    assert "bounded\n" in (result.envelope.projection.inline_text or "")


def test_small_output_is_marked_for_exact_passthrough(tmp_path: Path) -> None:
    result = run(request(AdapterMode.ENFORCE, tmp_path, "print('small')"))

    assert result.envelope is not None
    assert result.envelope.projection.extra == {
        "redaction": {"rules": []},
        "presentation": "exact-passthrough",
    }


def test_pod_health_adapter_returns_complete_summary(tmp_path: Path) -> None:
    header = "NAMESPACE NAME READY STATUS RESTARTS AGE IP NODE\n"
    rows = "".join(
        f"media pod-{index:04d} 1/1 Running 0 1h 10.0.0.{index} node-1\n"
        for index in range(600)
    )
    rows += "media failed 0/1 OOMKilled 0 1h 10.0.1.1 node-1\n"
    result = run(
        request(
            AdapterMode.ENFORCE,
            tmp_path,
            f"print({(header + rows)!r}, end='')",
            semantic_adapter="kubernetes.pod-health/v1",
        )
    )

    assert result.envelope is not None
    assert result.envelope.projection.extra is not None
    assert result.envelope.projection.extra["presentation"] == "semantic-complete"
    assert result.envelope.projection.extra["total_rows"] == 601
    assert result.envelope.projection.extra["health_predicates"]["OOMKilled"] == 1
    assert result.envelope.projection.extra["routine_rows_omitted"] == 600


def test_enforce_keeps_command_and_capture_status_distinct(tmp_path: Path) -> None:
    result = run(
        request(AdapterMode.ENFORCE, tmp_path, "print('too much')", max_capture_bytes=1)
    )

    assert result.command.exit_code == 0
    assert result.capture is not None
    assert result.capture.capture_status == "TRUNCATED"
    assert result.envelope is not None
    assert result.envelope.capture.status == "CAPTURE_TRUNCATED"
    assert result.receipt is not None
    assert result.receipt["capture"] == {
        "status": "CAPTURE_TRUNCATED",
        "stdout_bytes": 1,
        "stderr_bytes": 0,
    }


def test_receipt_is_json_safe_and_excludes_output_and_raw_paths(tmp_path: Path) -> None:
    secret = "unique-raw-output-secret"
    result = run(request(AdapterMode.ENFORCE, tmp_path, f"print({secret!r})"))

    assert result.receipt is not None
    serialized = json.dumps(result.receipt, sort_keys=True)
    assert secret not in serialized
    assert str(tmp_path.resolve()) not in serialized
    assert "inline_text" not in serialized
    assert "stdout.raw" not in serialized
    assert result.receipt["source"] == {
        "availability": "local-only",
        "host_id": "test-host",
    }


def test_receipt_carries_named_redaction_counts_without_sensitive_value(tmp_path: Path) -> None:
    protected = "registered" + "-output"
    result = run(
        request(
            AdapterMode.ENFORCE,
            tmp_path,
            f"print({protected!r})",
            exact_redaction_rules={"credential-registry": (protected,)},
        )
    )

    assert result.envelope is not None
    assert result.receipt is not None
    serialized_projection = json.dumps(result.envelope.to_dict()["projection"], sort_keys=True)
    serialized_receipt = json.dumps(result.receipt, sort_keys=True)
    assert serialized_projection.find(protected) == -1
    assert serialized_receipt.find(protected) == -1
    assert result.envelope.projection.extra == {
        "redaction": {"rules": [{"id": "credential-registry", "count": 1}]}
    }
    assert result.receipt["projection"]["redaction"] == {
        "rules": [{"id": "credential-registry", "count": 1}]
    }


def test_timeout_and_cwd_are_forwarded(tmp_path: Path) -> None:
    cwd = tmp_path / "work"
    cwd.mkdir()
    cwd_result = run(
        request(
            AdapterMode.SHADOW,
            tmp_path,
            "import os; print(os.getcwd())",
            cwd=cwd,
        )
    )
    timeout_result = run(
        request(AdapterMode.ENFORCE, tmp_path, "import time; time.sleep(60)", timeout=0.05)
    )

    assert cwd_result.envelope is not None
    assert cwd_result.envelope.projection.inline_text == f"{cwd}\n"
    assert timeout_result.command.timed_out is True
    assert timeout_result.command.signal == 9


def test_caller_bindings_are_passed_through_only(tmp_path: Path) -> None:
    bindings = {
        "action_id": "action-7",
        "sprint_id": "sprint-3",
        "session_id": "session-11",
        "correlation_id": "corr-13",
    }
    result = run(request(AdapterMode.SHADOW, tmp_path, "pass", bindings=bindings))

    assert result.envelope is not None
    assert result.envelope.bindings == bindings
    assert result.receipt is not None
    assert result.receipt["bindings"] == bindings
    assert list(tmp_path.rglob("*action*")) == []
    assert list(tmp_path.rglob("*sprint*")) == []
    assert list(tmp_path.rglob("*session*")) == []


def test_adapter_cancellation_terminates_group_and_leaves_incomplete_evidence(
    tmp_path: Path,
) -> None:
    child_pid_file = tmp_path / "child-pid"
    code = (
        "from pathlib import Path; import subprocess, sys, time; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        f"Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
        "time.sleep(60)"
    )

    async def cancel_running_adapter() -> None:
        task = asyncio.create_task(
            run_adapter(request(AdapterMode.ENFORCE, tmp_path, code, timeout=30))
        )
        for _ in range(100):
            if child_pid_file.exists():
                break
            await asyncio.sleep(0.01)
        assert child_pid_file.exists()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_running_adapter())

    child_pid = int(child_pid_file.read_text())
    for _ in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        pytest.fail("adapter cancellation leaked a child process")

    manifests = list((tmp_path / "spool" / "partial").glob("*/manifest.json"))
    assert len(manifests) == 1
    manifest = json.loads(manifests[0].read_text())
    assert manifest["capture_status"] == "INCOMPLETE"
    assert manifest["command"]["final_status"] == "UNKNOWN"
    assert manifest["termination"] == {
        "reason": "CALLER_CANCELLED",
        "caller_cancelled": True,
        "timed_out": False,
        "signals_sent": [9],
    }


def test_enforced_retrieval_bridge_is_bounded_redacted_and_never_reruns(tmp_path: Path) -> None:
    executions = tmp_path / "fixture-invocations"
    secret = "registered-retrieval-secret"
    prefix = "ordinary output record\n"
    middle = f"known-middle-marker secret={secret}\n"
    suffix = "ordinary output record\n"
    code = (
        "from pathlib import Path; import sys; "
        f"marker = Path({str(executions)!r}); "
        "marker.write_text(str(int(marker.read_text()) + 1) if marker.exists() else '1'); "
        f"sys.stdout.write({prefix!r} * 80 + {middle!r} + {suffix!r} * 80)"
    )
    adapter_request = request(
        AdapterMode.ENFORCE,
        tmp_path,
        code,
        projection_limits=ProjectionLimits(96, 4, 24),
        exact_redaction_rules={"fixture-secret": (secret,)},
    )
    result = run(adapter_request)

    assert result.envelope is not None
    assert "known-middle-marker" not in (result.envelope.projection.inline_text or "")
    start = len(prefix.encode()) * 80
    retrieved = retrieve_adapter_slice(
        adapter_request,
        result.envelope.capture_ref,
        stream="stdout",
        start=start,
        end=start + len(middle.encode()),
        max_bytes=256,
    )

    assert retrieved.status is RetrievalStatus.AVAILABLE
    assert "known-middle-marker" in (retrieved.inline_text or "")
    assert secret not in (retrieved.inline_text or "")
    assert retrieved.redacted is True
    assert retrieved.projection_bytes <= adapter_request.projection_limits.max_bytes
    assert executions.read_text() == "1"


def test_local_pilot_reports_bypass_shadow_and_enforce_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = run_local_pilot(tmp_path, monkeypatch)

    assert set(report) == {"bypass", "shadow", "enforce", "qualitative_assessment"}
    bypass = report["bypass"]
    shadow = report["shadow"]
    enforce = report["enforce"]
    assert isinstance(bypass, dict)
    assert isinstance(shadow, dict)
    assert isinstance(enforce, dict)
    assert bypass["raw_bytes"] > 0
    assert bypass["exposed_bytes"] == bypass["raw_bytes"]
    assert bypass["estimated_tokens"] > 0
    assert bypass["wrapper_overhead_ms"] == 0.0
    for measurement in (shadow, enforce):
        assert measurement["raw_bytes"] == bypass["raw_bytes"]
        assert 0 < measurement["exposed_bytes"] < measurement["raw_bytes"]
        assert 0 < measurement["estimated_tokens"] < bypass["estimated_tokens"]
        assert measurement["retrieval_count"] == 0
        assert measurement["wall_time_ms"] >= 0
    assert shadow["retrieval_count"] == enforce["retrieval_count"] == 0
    assert report["qualitative_assessment"] == {
        "harness_managed": "direct command execution and ordinary command outcome",
        "outctl_adds": "bounded projection, local capture metrics, and no-rerun retrieval",
    }


def test_g01_long_session_pilot_bounds_exposure_without_retrieval_or_rerun(
    tmp_path: Path,
) -> None:
    """Measure a representative long-session class without exposing its raw body."""
    execution_marker = tmp_path / "executions"
    policy_digest = "sha256:" + "1" * 64
    # 179,200 deterministic estimated tokens at the documented v1 estimator.
    # The child constructs the body itself, so neither this test nor failures
    # contain the large raw output.
    code = (
        "from pathlib import Path; import sys; "
        f"marker = Path({str(execution_marker)!r}); "
        "marker.write_text(str(int(marker.read_text()) + 1) if marker.exists() else '1'); "
        "line = b'representative bash output record 000000000000000000000000000000\\n'; "
        "sys.stdout.buffer.write(line * 11200)"
    )
    quota_bytes = 800_000
    result = run(
        request(
            AdapterMode.ENFORCE,
            tmp_path,
            code,
            max_capture_bytes=quota_bytes,
            projection_limits=ProjectionLimits(4_096, 128, 1_024),
        )
    )

    assert result.capture is not None
    assert result.envelope is not None
    assert result.receipt is not None
    raw_bytes = result.capture.stdout_bytes + result.capture.stderr_bytes
    report = {
        "raw_estimated_tokens": result.envelope.metrics["raw_estimated_tokens"],
        "exposed_estimated_tokens": result.envelope.metrics[
            "exposed_estimated_tokens"
        ],
        "retrieved_estimated_tokens": 0,
        "retrieval_count": 0,
        "policy_digest": result.receipt["policy"]["digest"],
    }

    assert result.command.exit_code == 0
    assert execution_marker.read_text() == "1"
    assert result.capture.capture_status == "COMPLETE"
    assert 0 < raw_bytes <= quota_bytes
    assert report["raw_estimated_tokens"] >= 178_000
    assert report["exposed_estimated_tokens"] * 2 <= report["raw_estimated_tokens"]
    assert report["retrieved_estimated_tokens"] == report["retrieval_count"] == 0
    assert report["policy_digest"] == policy_digest


def test_fresh_installed_interpreter_imports_adapter_without_network_or_external_state() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import sys; "
                "from outctl.adapter import AdapterMode, run_adapter; assert AdapterMode.BYPASS"
            ),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    assert result.returncode == 0
