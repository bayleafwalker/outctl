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
from outctl.retrieval import RetrievalStatus, slice_stream

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class AdapterMode(StrEnum):
    """Opt-in behavior selected by the embedding caller."""

    BYPASS = "bypass"
    SHADOW = "shadow"
    ENFORCE = "enforce"

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        default: AdapterMode | str | None = None,
    ) -> AdapterMode:
        """Resolve the documented feature flags without changing typed callers.

        ``OUTCTL_ENABLED=0`` is the break-glass switch and always selects
        bypass.  Otherwise ``OUTCTL_MODE`` selects one of the three explicit
        modes, falling back to ``default`` when it is absent.
        """
        environment = os.environ if environ is None else environ
        enabled = environment.get("OUTCTL_ENABLED")
        if enabled is not None and enabled not in {"0", "1"}:
            raise ValueError("OUTCTL_ENABLED must be '0' or '1'")
        if enabled == "0":
            return cls.BYPASS
        configured = environment.get("OUTCTL_MODE")
        if configured is None:
            return cls.BYPASS if default is None else cls(default)
        try:
            return cls(configured.casefold())
        except ValueError as error:
            values = ", ".join(mode.value for mode in cls)
            raise ValueError(f"OUTCTL_MODE must be one of: {values}") from error


def resolve_adapter_mode(
    configured: AdapterMode | str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    default: AdapterMode = AdapterMode.BYPASS,
) -> AdapterMode:
    """Select a mode from typed/configured input or documented environment.

    An explicitly configured mode has priority over ``OUTCTL_MODE``.  The
    ``OUTCTL_ENABLED=0`` break-glass flag still forces bypass so a harness can
    be rolled back without changing its typed configuration.
    """
    environment = os.environ if environ is None else environ
    # Validate the environment even when a typed setting wins, so malformed
    # feature-flag configuration cannot silently become an enforce setting.
    environment_mode = AdapterMode.from_environment(environment, default=default)
    if environment.get("OUTCTL_ENABLED") == "0":
        return AdapterMode.BYPASS
    if configured is None:
        return environment_mode
    if isinstance(configured, AdapterMode):
        return configured
    try:
        return AdapterMode(configured.casefold())
    except ValueError as error:
        values = ", ".join(mode.value for mode in AdapterMode)
        raise ValueError(f"configured mode must be one of: {values}") from error


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
    exact_redaction_rules: Mapping[str, Sequence[bytes | str]] | None = None

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
        if self.exact_redaction_rules is not None:
            object.__setattr__(
                self,
                "exact_redaction_rules",
                {
                    identifier: tuple(values)
                    for identifier, values in self.exact_redaction_rules.items()
                },
            )


@dataclass(frozen=True)
class AdapterResult:
    """Command outcome plus optional outctl artifacts."""

    mode: AdapterMode
    command: CommandResult
    # This is the harness-facing ordinary result in bypass and shadow mode.
    # It deliberately remains a command result rather than an outctl policy
    # judgment; action/audit lifecycle decisions remain with the caller.
    ordinary_result: CommandResult
    capture: CaptureResult | None = None
    envelope: CommandResultEnvelope | None = None
    receipt: dict[str, JsonValue] | None = None


@dataclass(frozen=True)
class AdapterRetrievalResult:
    """A bounded, redacted retrieval view suitable for a harness tool result."""

    capture_ref: str
    stream: str
    start: int
    end: int
    status: RetrievalStatus
    inline_text: str | None = None
    projection_bytes: int = 0
    estimated_tokens: int = 0
    lossy: bool = False
    redacted: bool = False
    detail: str | None = None


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
        "source": {
            "availability": envelope.capture.source.availability,
            "host_id": envelope.capture.source.host_id,
        },
        "projection": {
            "id": envelope.projection.projection_id,
            "sha256": envelope.projection.sha256,
            "bytes": envelope.projection.bytes,
            "lines": envelope.projection.lines,
            "estimated_tokens": envelope.projection.estimated_tokens,
            "lossy": envelope.projection.lossy,
            "redacted": envelope.projection.redacted,
            "redaction": envelope.projection.extra["redaction"]
            if envelope.projection.extra is not None
            else {"rules": []},
        },
    }


def _opaque_capture_source(capture_id: str) -> str:
    """Return a locator that identifies evidence without disclosing its path."""
    return f"outctl://capture/{capture_id}"


def _capture_id_from_ref(capture_ref: str) -> str:
    """Extract one adapter-issued ID from a complete opaque capture reference."""
    prefix = "outctl://capture/"
    manifest_marker = "/manifest/sha256/"
    if not capture_ref.startswith(prefix):
        raise ValueError("capture_ref is not an outctl capture reference")
    capture_id, marker, digest = capture_ref[len(prefix) :].partition(manifest_marker)
    if not capture_id or marker != manifest_marker or len(digest) != 64:
        raise ValueError("capture_ref is malformed")
    if any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("capture_ref digest is malformed")
    if any(character not in "0123456789abcdef" for character in capture_id):
        raise ValueError("capture_ref id is malformed")
    return capture_id


def retrieve_adapter_slice(
    request: AdapterRequest,
    capture_ref: str,
    *,
    stream: str,
    start: int,
    end: int,
    max_bytes: int | None = None,
) -> AdapterRetrievalResult:
    """Read one existing capture range and expose only a safe projection.

    This is intentionally a read-only bridge: it resolves no command and
    never carries raw bytes or a local spool path back across the harness
    boundary.
    """
    if request.mode is AdapterMode.BYPASS:
        raise ValueError("bypass mode has no adapter capture retrieval")
    assert request.spool_root is not None
    retrieval_limit = request.projection_limits.max_bytes if max_bytes is None else max_bytes
    if retrieval_limit <= 0:
        raise ValueError("max_bytes must be positive")
    capture_id = _capture_id_from_ref(capture_ref)
    retrieved = slice_stream(
        request.spool_root,
        capture_id,
        stream,
        start,
        end,
        max_bytes=retrieval_limit,
    )
    if retrieved.status is not RetrievalStatus.AVAILABLE:
        return AdapterRetrievalResult(
            capture_ref=capture_ref,
            stream=stream,
            start=start,
            end=end,
            status=retrieved.status,
            detail=retrieved.detail,
        )
    projection = project_bytes(
        retrieved.data,
        exact_values=request.exact_values,
        exact_redaction_rules=request.exact_redaction_rules,
        limits=request.projection_limits,
    )
    return AdapterRetrievalResult(
        capture_ref=capture_ref,
        stream=stream,
        start=retrieved.start,
        end=retrieved.end,
        status=RetrievalStatus.AVAILABLE,
        inline_text=projection.text,
        projection_bytes=projection.bytes,
        estimated_tokens=projection.estimated_tokens,
        lossy=projection.lossy,
        redacted=projection.redacted,
    )


async def run_adapter(request: AdapterRequest) -> AdapterResult:
    """Execute one request without taking ownership of caller workflow state."""
    if request.mode is AdapterMode.BYPASS:
        command = await _run_bypass(request)
        return AdapterResult(
            mode=request.mode,
            command=command,
            ordinary_result=command,
        )

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
        exact_redaction_rules=request.exact_redaction_rules,
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
        source_path=_opaque_capture_source(capture.capture_id),
    )
    return AdapterResult(
        mode=request.mode,
        command=capture.command,
        ordinary_result=capture.command,
        capture=capture,
        envelope=envelope,
        receipt=_receipt(request, capture, envelope),
    )
