"""Small opt-in library adapter for direct execution and outctl capture."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from outctl.capture.runner import CaptureResult, CommandResult, capture_command
from outctl.envelope import build_result_envelope
from outctl.models import CommandResultEnvelope, CommandResultInvocation
from outctl.projection import ProjectionLimits, project_bytes

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class AdapterMode(StrEnum):
    """Opt-in behavior selected by the embedding caller."""

    BYPASS = "bypass"
    SHADOW = "shadow"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class AdapterIdentity:
    """Local execution identity supplied by the embedding caller."""

    host_id: str
    harness: str


@dataclass(frozen=True)
class AdapterRequest:
    """All inputs needed for one adapter execution."""

    mode: AdapterMode
    argv: Sequence[str]
    policy_ref: str
    policy_digest: str
    identity: AdapterIdentity
    bindings: Mapping[str, str | None] = field(default_factory=dict)
    spool_root: Path | None = None
    cwd: Path | None = None
    timeout: float | None = None
    max_capture_bytes: int = 16 * 1024 * 1024
    projection_limits: ProjectionLimits = field(
        default_factory=lambda: ProjectionLimits(65_536, 2_000, 16_000)
    )
    exact_values: Sequence[bytes | str] = ()

    def __post_init__(self) -> None:
        if isinstance(self.argv, (str, bytes)) or not self.argv:
            raise TypeError("argv must be a non-empty sequence of strings")
        argv = tuple(self.argv)
        if any(not isinstance(argument, str) for argument in argv):
            raise TypeError("argv must contain only strings")
        if self.mode is not AdapterMode.BYPASS and self.spool_root is None:
            raise ValueError("spool_root is required for shadow and enforce modes")
        if self.max_capture_bytes < 0:
            raise ValueError("max_capture_bytes must be non-negative")
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "bindings", dict(self.bindings))
        object.__setattr__(self, "exact_values", tuple(self.exact_values))


@dataclass(frozen=True)
class AdapterResult:
    """Command outcome plus optional outctl artifacts."""

    mode: AdapterMode
    command: CommandResult
    capture: CaptureResult | None = None
    envelope: CommandResultEnvelope | None = None
    receipt: dict[str, JsonValue] | None = None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _kill_group(process: asyncio.subprocess.Process) -> None:
    if process.pid is None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


async def _run_bypass(request: AdapterRequest) -> CommandResult:
    process = await asyncio.create_subprocess_exec(
        *request.argv,
        cwd=str(request.cwd) if request.cwd is not None else None,
        start_new_session=True,
    )
    timed_out = False
    cancelled = False
    signals_sent: tuple[int, ...] = ()
    try:
        await asyncio.wait_for(process.wait(), timeout=request.timeout)
    except TimeoutError:
        timed_out = True
        signals_sent = (signal.SIGKILL,)
        _kill_group(process)
        await process.wait()
    except asyncio.CancelledError:
        cancelled = True
        signals_sent = (signal.SIGKILL,)
        _kill_group(process)
        await process.wait()
        raise

    returncode = process.returncode
    return CommandResult(
        started=True,
        exit_code=returncode if returncode is not None and returncode >= 0 else None,
        signal=-returncode if returncode is not None and returncode < 0 else None,
        timed_out=timed_out,
        cancelled=cancelled,
        signals_sent=signals_sent,
    )


def _capture_chunks(capture: CaptureResult) -> Iterator[bytes]:
    for stream in ("stdout.raw", "stderr.raw"):
        with (capture.path / stream).open("rb") as raw:
            while chunk := raw.read(64 * 1024):
                yield chunk


def _receipt(
    request: AdapterRequest, capture: CaptureResult, envelope: CommandResultEnvelope
) -> dict[str, JsonValue]:
    """Return compact metadata with no command output or local raw-data path."""
    return {
        "schema_version": "outctl.adapter.receipt/v1alpha1",
        "mode": request.mode.value,
        "capture_id": capture.capture_id,
        "capture_ref": envelope.capture_ref,
        "bindings": dict(request.bindings),
        "policy": {"ref": request.policy_ref, "digest": request.policy_digest},
        "command": {
            "started": capture.command.started,
            "exit_code": capture.command.exit_code,
            "signal": capture.command.signal,
            "timed_out": capture.command.timed_out,
            "cancelled": capture.command.cancelled,
        },
        "capture": {
            "status": envelope.capture.status,
            "stdout_bytes": capture.stdout_bytes,
            "stderr_bytes": capture.stderr_bytes,
        },
        "projection": {
            "id": envelope.projection.projection_id,
            "sha256": envelope.projection.sha256,
            "bytes": envelope.projection.bytes,
            "lines": envelope.projection.lines,
            "estimated_tokens": envelope.projection.estimated_tokens,
            "lossy": envelope.projection.lossy,
            "redacted": envelope.projection.redacted,
        },
    }


async def run_adapter(request: AdapterRequest) -> AdapterResult:
    """Execute one request without taking ownership of caller workflow state."""
    if request.mode is AdapterMode.BYPASS:
        return AdapterResult(mode=request.mode, command=await _run_bypass(request))

    assert request.spool_root is not None
    started_at = _utc_now()
    started = time.monotonic()
    capture = await capture_command(
        request.argv,
        request.spool_root,
        max_bytes=request.max_capture_bytes,
        timeout=request.timeout,
        cwd=request.cwd,
        required_capture=request.mode is AdapterMode.ENFORCE,
    )
    ended_at = _utc_now()
    duration_ms = round((time.monotonic() - started) * 1000)
    projection = project_bytes(
        _capture_chunks(capture),
        exact_values=request.exact_values,
        limits=request.projection_limits,
    )
    invocation = CommandResultInvocation(
        argv_display=list(request.argv),
        shell=False,
        cwd=str(request.cwd) if request.cwd is not None else str(Path.cwd()),
        host_id=request.identity.host_id,
        harness=request.identity.harness,
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=duration_ms,
    )
    envelope = build_result_envelope(
        capture,
        projection,
        invocation,
        policy_ref=request.policy_ref,
        policy_digest=request.policy_digest,
        mode=request.mode.value,
        bindings=request.bindings,
    )
    return AdapterResult(
        mode=request.mode,
        command=capture.command,
        capture=capture,
        envelope=envelope,
        receipt=_receipt(request, capture, envelope),
    )
