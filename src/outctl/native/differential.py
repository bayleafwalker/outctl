"""Bounded test-only differential runner for Python and Rust capture engines."""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from outctl.capture.runner import capture_command


@dataclass(frozen=True)
class EngineObservation:
    engine: str
    command: dict[str, object]
    capture_status: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    elapsed_ms: float


@dataclass(frozen=True)
class DifferentialResult:
    passed: bool
    exact_mismatches: tuple[str, ...]
    semantic_mismatches: tuple[str, ...]
    intentional_differences: tuple[str, ...]
    python: EngineObservation
    rust: EngineObservation


def compare_capture_engines(
    argv: list[str],
    spool_root: Path,
    *,
    native_binary: Path,
    max_bytes: int,
    timeout: float | None = None,
    cwd: Path | None = None,
    harness_timeout: float = 30.0,
) -> DifferentialResult:
    """Execute one deterministic fixture once per engine and compare W3 fields.

    This helper is intentionally unsuitable for stateful production commands:
    differential execution runs the argv twice. It retains raw bytes only in
    the two private fixture spools and returns metadata/hashes.
    """
    python_root = spool_root / "python"
    rust_root = spool_root / "rust"
    started = time.monotonic()
    if harness_timeout <= 0:
        raise ValueError("harness_timeout must be positive")
    python_result = asyncio.run(
        asyncio.wait_for(
            capture_command(argv, python_root, max_bytes=max_bytes, timeout=timeout, cwd=cwd),
            timeout=harness_timeout,
        )
    )
    python_elapsed = (time.monotonic() - started) * 1000
    command = [
        str(native_binary),
        "run",
        "--spool-root",
        str(rust_root),
        "--max-bytes",
        str(max_bytes),
    ]
    if timeout is not None:
        command.extend(("--timeout-ms", str(max(0, round(timeout * 1000)))))
    if cwd is not None:
        command.extend(("--cwd", str(cwd)))
    command.extend(("--", *argv))
    started = time.monotonic()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=harness_timeout,
    )
    rust_elapsed = (time.monotonic() - started) * 1000
    if not completed.stdout:
        raise RuntimeError(f"native differential run returned no JSON: {completed.stderr}")
    native = json.loads(completed.stdout)
    python = EngineObservation(
        engine="python-reference",
        command={
            "started": python_result.command.started,
            "exit_code": python_result.command.exit_code,
            "signal": python_result.command.signal,
            "timed_out": python_result.command.timed_out,
            "cancelled": python_result.command.cancelled,
        },
        capture_status=python_result.capture_status,
        stdout_bytes=python_result.stdout_bytes,
        stderr_bytes=python_result.stderr_bytes,
        stdout_sha256=python_result.stdout_sha256,
        stderr_sha256=python_result.stderr_sha256,
        elapsed_ms=python_elapsed,
    )
    rust = EngineObservation(
        engine="rust-native",
        command={key: native["command"][key] for key in python.command},
        capture_status=native["capture_status"],
        stdout_bytes=native["stdout_bytes"],
        stderr_bytes=native["stderr_bytes"],
        stdout_sha256=native["stdout_sha256"],
        stderr_sha256=native["stderr_sha256"],
        elapsed_ms=rust_elapsed,
    )
    exact_fields = (
        "stdout_bytes",
        "stderr_bytes",
        "stdout_sha256",
        "stderr_sha256",
    )
    exact = tuple(
        field for field in exact_fields if getattr(python, field) != getattr(rust, field)
    )
    semantic = tuple(
        field
        for field in ("command", "capture_status")
        if getattr(python, field) != getattr(rust, field)
    )
    return DifferentialResult(
        passed=not exact and not semantic,
        exact_mismatches=exact,
        semantic_mismatches=semantic,
        intentional_differences=("engine", "elapsed_ms", "capture_id", "path", "event_index"),
        python=python,
        rust=rust,
    )


__all__ = [
    "DifferentialResult",
    "EngineObservation",
    "compare_capture_engines",
]
