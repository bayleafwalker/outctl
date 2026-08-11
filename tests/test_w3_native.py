from __future__ import annotations

import asyncio
import json
import shutil
import stat
import subprocess
import sys
import time
from functools import lru_cache
from pathlib import Path

import pytest

from outctl.capture import capture_command
from outctl.native import EngineChoice, NativeEngineUnavailable, select_engine
from outctl.native.differential import compare_capture_engines
from outctl.retrieval import RetrievalStatus, inspect_capture, verify_capture

ROOT = Path(__file__).parents[1]

pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required")


@lru_cache
def _native_binary() -> Path:
    subprocess.run(
        ["cargo", "build", "--quiet", "--package", "outctl-cli", "--bin", "outctl-native"],
        cwd=ROOT,
        check=True,
    )
    return ROOT / "target" / "debug" / "outctl-native"


def _native_run(
    root: Path,
    argv: list[str],
    *,
    max_bytes: int = 1024 * 1024,
    timeout_ms: int | None = None,
    workspace_id: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    command = [
        str(_native_binary()),
        "run",
        "--spool-root",
        str(root),
        "--max-bytes",
        str(max_bytes),
    ]
    if timeout_ms is not None:
        command.extend(("--timeout-ms", str(timeout_ms)))
    if workspace_id is not None:
        command.extend(("--workspace-id", workspace_id))
    command.extend(("--", *argv))
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
    return completed, json.loads(completed.stdout)


def test_exact_hash_and_process_differential_with_timings(tmp_path: Path) -> None:
    result = compare_capture_engines(
        [
            sys.executable,
            "-c",
            "import os; os.write(1,b'alpha\\x00omega\\n'); os.write(2,b'warn\\n')",
        ],
        tmp_path,
        native_binary=_native_binary(),
        max_bytes=1024,
    )
    assert result.passed, result
    assert result.exact_mismatches == ()
    assert result.semantic_mismatches == ()
    assert result.python.elapsed_ms >= 0
    assert result.rust.elapsed_ms >= 0


@pytest.mark.parametrize(
    ("code", "timeout"),
    [
        ("raise SystemExit(7)", None),
        ("import os,signal; os.kill(os.getpid(), signal.SIGTERM)", None),
        ("import time; print('started', flush=True); time.sleep(60)", 0.1),
    ],
)
def test_nonzero_signal_and_timeout_process_parity(
    tmp_path: Path, code: str, timeout: float | None
) -> None:
    result = compare_capture_engines(
        [sys.executable, "-c", code],
        tmp_path,
        native_binary=_native_binary(),
        max_bytes=1024,
        timeout=timeout,
    )
    assert result.passed, result


def test_native_capture_is_python_readable_and_private(tmp_path: Path) -> None:
    completed, result = _native_run(
        tmp_path,
        [sys.executable, "-c", "import os; os.write(1,b'hello\\n')"],
        workspace_id="workspace-owned",
    )
    assert completed.returncode == 0
    capture_id = str(result["capture_id"])
    inspected = inspect_capture(tmp_path, capture_id)
    assert inspected.status is RetrievalStatus.AVAILABLE
    assert (
        inspect_capture(tmp_path, capture_id, expected_workspace_id="workspace-owned").status
        is RetrievalStatus.AVAILABLE
    )
    assert (
        inspect_capture(tmp_path, capture_id, expected_workspace_id="workspace-other").status
        is RetrievalStatus.DENIED
    )
    assert verify_capture(tmp_path, capture_id).status is RetrievalStatus.AVAILABLE
    capture_path = Path(str(result["path"]))
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "captures").stat().st_mode) == 0o700
    assert stat.S_IMODE(capture_path.stat().st_mode) == 0o700
    for name in ("stdout.raw", "stderr.raw", "events.ndjson", "manifest.json"):
        assert stat.S_IMODE((capture_path / name).stat().st_mode) == 0o600
    manifest = json.loads((capture_path / "manifest.json").read_text())
    assert manifest["compatibility"] == {
        "unknown_fields_ignored": True,
        "v1_manifest_byte_exact": False,
        "v1_reader": "readable",
        "v1_stream_bytes_preserved": True,
        "v1_writer": "python-reference-only",
    }
    assert result["timings"]["command_ms"] >= 0
    assert result["timings"]["drain_ms"] >= 0
    assert result["timings"]["finalize_ms"] >= 0
    assert result["timings"]["drain_grace_exhausted"] is False


def test_python_capture_is_native_readable_and_verifiable(tmp_path: Path) -> None:
    result = asyncio.run(
        capture_command(
            [sys.executable, "-c", "print('python-reference')"],
            tmp_path,
            max_bytes=1024,
        )
    )
    inspected = subprocess.run(
        [str(_native_binary()), "inspect", "--spool-root", str(tmp_path), result.capture_id],
        check=False,
        capture_output=True,
        text=True,
    )
    assert inspected.returncode == 0
    assert json.loads(inspected.stdout)["capture_status"] == "COMPLETE"
    verified = subprocess.run(
        [str(_native_binary()), "verify", "--spool-root", str(tmp_path), result.capture_id],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0
    assert json.loads(verified.stdout)["status"] == "AVAILABLE"


def test_native_recovery_marks_abandoned_python_partial_without_execution(tmp_path: Path) -> None:
    partial = tmp_path / "partial" / "abandoned.partial"
    partial.mkdir(parents=True)
    marker = tmp_path / "must-not-execute"
    completed = subprocess.run(
        [str(_native_binary()), "recover", "--spool-root", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["records"][0]["capture_id"] == "abandoned"
    assert not marker.exists()
    assert inspect_capture(tmp_path, "abandoned").status is RetrievalStatus.INCOMPLETE
    manifest = json.loads((partial / "manifest.json").read_text())
    assert manifest["termination"]["caller_cancelled"] is None
    assert manifest["termination"]["timed_out"] is None
    for name in ("manifest.json", "recovery.json"):
        assert stat.S_IMODE((partial / name).stat().st_mode) == 0o600


def test_quota_is_shared_and_exhaustion_does_not_deadlock(tmp_path: Path) -> None:
    code = "import os; [(os.write(1,b'o'*65536),os.write(2,b'e'*65536)) for _ in range(32)]"
    completed, result = _native_run(
        tmp_path,
        [sys.executable, "-c", code],
        max_bytes=4097,
        timeout_ms=5000,
    )
    assert completed.returncode == 0
    assert result["capture_status"] == "TRUNCATED"
    assert result["stdout_bytes"] + result["stderr_bytes"] == 4097
    assert result["command"]["exit_code"] == 0


def test_timeout_kills_the_child_process_group_without_orphan(tmp_path: Path) -> None:
    marker = tmp_path / "leaked-child"
    child_code = (
        "import pathlib,time; time.sleep(.6); "
        f"pathlib.Path({str(marker)!r}).write_text('leaked')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); time.sleep(60)"
    )
    completed, result = _native_run(
        tmp_path / "spool",
        [sys.executable, "-c", parent_code],
        timeout_ms=100,
    )
    assert completed.returncode == 137
    assert result["command"] == {
        "cancelled": False,
        "exit_code": None,
        "signal": 9,
        "signals_sent": [9],
        "started": True,
        "timed_out": True,
    }
    time.sleep(0.7)
    assert not marker.exists()


def test_inherited_pipe_descendant_cannot_hang_or_outlive_capture(tmp_path: Path) -> None:
    marker = tmp_path / "background-child"
    child_code = (
        "import pathlib,time; time.sleep(.7); "
        f"pathlib.Path({str(marker)!r}).write_text('leaked')"
    )
    parent_code = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); print('parent-done')"
    )
    started = time.monotonic()
    completed, result = _native_run(
        tmp_path / "spool",
        [sys.executable, "-c", parent_code],
    )
    elapsed = time.monotonic() - started
    assert completed.returncode == 0
    assert elapsed < 2
    assert result["command"]["exit_code"] == 0
    assert result["timings"]["drain_grace_exhausted"] is True
    time.sleep(0.8)
    assert not marker.exists()


def test_unsafe_symlinked_spools_and_capture_paths_are_denied(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    root_link = tmp_path / "spool-link"
    root_link.symlink_to(target, target_is_directory=True)
    failed = subprocess.run(
        [
            str(_native_binary()),
            "run",
            "--spool-root",
            str(root_link),
            "--",
            sys.executable,
            "-c",
            "print('must-not-run')",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 125
    assert not list(target.iterdir())

    _completed, result = _native_run(
        tmp_path / "safe",
        [sys.executable, "-c", "print('safe')"],
    )
    capture_path = Path(str(result["path"]))
    (tmp_path / "safe" / "captures" / "linked").symlink_to(
        capture_path, target_is_directory=True
    )
    denied = subprocess.run(
        [
            str(_native_binary()),
            "inspect",
            "--spool-root",
            str(tmp_path / "safe"),
            "linked",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert denied.returncode == 1
    assert json.loads(denied.stdout)["status"] == "DENIED"


def test_native_memory_stays_bounded_after_capture_quota(tmp_path: Path) -> None:
    command = [
        str(_native_binary()),
        "run",
        "--spool-root",
        str(tmp_path),
        "--max-bytes",
        "1",
        "--timeout-ms",
        "10000",
        "--",
        sys.executable,
        "-c",
        "import os,time; [(os.write(1,b'x'*1048576),time.sleep(.001)) for _ in range(96)]",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak_kib = 0
    while process.poll() is None:
        try:
            status = Path(f"/proc/{process.pid}/status").read_text()
        except FileNotFoundError:
            break
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                peak_kib = max(peak_kib, int(line.split()[1]))
        time.sleep(0.005)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, stderr
    result = json.loads(stdout)
    assert result["capture_status"] == "TRUNCATED"
    assert result["stdout_bytes"] == 1
    assert peak_kib < 64 * 1024


def test_engine_selection_is_explicit_and_rollback_safe(tmp_path: Path) -> None:
    assert select_engine(environment={}).choice is EngineChoice.PYTHON_REFERENCE
    rollback = select_engine(environment={"OUTCTL_ENABLED": "0", "OUTCTL_ENGINE": "rust"})
    assert rollback.choice is EngineChoice.PYTHON_REFERENCE
    with pytest.raises(NativeEngineUnavailable):
        select_engine("rust", environment={}, native_executable=tmp_path / "missing")
    selected = select_engine("rust", environment={}, native_executable=_native_binary())
    assert selected.choice is EngineChoice.RUST_NATIVE
    assert selected.executable == _native_binary().resolve()
