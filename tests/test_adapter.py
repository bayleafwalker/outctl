from __future__ import annotations

import asyncio
import json
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
    return report


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


def test_shadow_returns_command_outcome_and_observation(tmp_path: Path) -> None:
    result = run(request(AdapterMode.SHADOW, tmp_path, "print('observed'); raise SystemExit(7)"))

    assert result.command.exit_code == 7
    assert result.capture is not None
    assert result.capture.capture_status == "COMPLETE"
    assert result.envelope is not None
    assert result.envelope.command.exit_code == 7
    assert result.envelope.projection.inline_text == "observed\n"
    assert result.receipt is not None
    assert result.receipt["mode"] == "shadow"


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


def test_action_and_audit_bindings_are_passed_through_only(tmp_path: Path) -> None:
    bindings = {"action_id": "action-7", "audit_id": "audit-9"}
    result = run(request(AdapterMode.SHADOW, tmp_path, "pass", bindings=bindings))

    assert result.envelope is not None
    assert result.envelope.bindings == bindings
    assert result.receipt is not None
    assert result.receipt["bindings"] == bindings
    assert list(tmp_path.rglob("*action*")) == []
    assert list(tmp_path.rglob("*audit*")) == []


def test_local_pilot_reports_bypass_shadow_and_enforce_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = run_local_pilot(tmp_path, monkeypatch)

    assert set(report) == {"bypass", "shadow", "enforce"}
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
