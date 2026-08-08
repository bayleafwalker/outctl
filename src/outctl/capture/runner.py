"""Bounded direct-argv subprocess capture for Linux non-PTY execution."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import time
import uuid
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from outctl.capture.storage import StreamWriter, private_dir, write_json

_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class CommandResult:
    started: bool
    exit_code: int | None
    signal: int | None
    timed_out: bool
    cancelled: bool
    signals_sent: tuple[int, ...]


@dataclass(frozen=True)
class CaptureResult:
    capture_id: str
    path: Path
    command: CommandResult
    capture_status: Literal["COMPLETE", "TRUNCATED", "CAPTURE_FAILED"]
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    event_sha256: str
    event_count: int


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not argv:
        raise TypeError("argv must be a non-empty sequence of strings, never a shell command")
    result = tuple(argv)
    if any(not isinstance(argument, str) for argument in result):
        raise TypeError("argv must contain only strings")
    return result


def _kill_group(process: asyncio.subprocess.Process) -> None:
    if process.pid is None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


async def capture_command(
    argv: Sequence[str],
    root: Path,
    *,
    max_bytes: int,
    timeout: float | None = None,
    cwd: Path | None = None,
    required_capture: bool = False,
) -> CaptureResult:
    """Run ``argv`` without a shell and atomically finalize a bounded spool.

    Every pipe is drained to EOF even once the retained byte quota is exhausted.
    The quota controls disk retention only, never pipe drainage or command status.
    """
    command = _validate_argv(argv)
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")

    private_dir(root)
    partial_root = root / "partial"
    captures_root = root / "captures"
    private_dir(partial_root)
    private_dir(captures_root)
    capture_id = uuid.uuid4().hex
    partial = partial_root / f"{capture_id}.partial"
    partial.mkdir(mode=0o700)
    os.chmod(partial, 0o700)
    stdout = StreamWriter.create(partial / "stdout.raw")
    stderr = StreamWriter.create(partial / "stderr.raw")
    event_path = partial / "events.ndjson"
    event_file = event_path.open("x", encoding="utf-8")
    os.chmod(event_path, 0o600)
    event_hash = hashlib.sha256()
    captured = 0
    truncated = False
    capture_failed = False
    sequence = 0

    def record(stream: str, offset: int, length: int) -> None:
        nonlocal sequence
        event = {
            "seq": sequence,
            "stream": stream,
            "monotonic_ns": time.monotonic_ns(),
            "offset": offset,
            "length": length,
        }
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        event_file.write(line)
        event_hash.update(line.encode("utf-8"))
        sequence += 1

    def retain(writer: StreamWriter, stream: str, chunk: bytes) -> None:
        nonlocal captured, truncated
        remaining = max_bytes - captured
        if remaining <= 0:
            truncated = truncated or bool(chunk)
            return
        retained = chunk[:remaining]
        offset = writer.retained_bytes
        writer.write(retained)
        record(stream, offset, len(retained))
        captured += len(retained)
        truncated = truncated or len(retained) != len(chunk)

    async def drain(reader: asyncio.StreamReader, writer: StreamWriter, stream: str) -> None:
        nonlocal capture_failed
        writable = True
        while chunk := await reader.read(_CHUNK_SIZE):
            if not writable:
                continue
            try:
                retain(writer, stream, chunk)
            except OSError:
                # Storage failure never permits pipe backpressure. Required
                # capture additionally terminates the isolated child group.
                writable = False
                capture_failed = True
                if required_capture:
                    _kill_group(process)

    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd) if cwd is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    drainers = [
        asyncio.create_task(drain(process.stdout, stdout, "stdout")),
        asyncio.create_task(drain(process.stderr, stderr, "stderr")),
    ]
    timed_out = False
    cancelled = False
    signals_sent: tuple[int, ...] = ()
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
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
    finally:
        await asyncio.gather(*drainers)
        stdout.close()
        stderr.close()
        event_file.flush()
        os.fsync(event_file.fileno())
        event_file.close()

    returncode = process.returncode
    command_result = CommandResult(
        started=True,
        exit_code=returncode if returncode is not None and returncode >= 0 else None,
        signal=-returncode if returncode is not None and returncode < 0 else None,
        timed_out=timed_out,
        cancelled=cancelled,
        signals_sent=signals_sent,
    )
    capture_status: Literal["COMPLETE", "TRUNCATED", "CAPTURE_FAILED"]
    if capture_failed:
        capture_status = "CAPTURE_FAILED"
    else:
        capture_status = "TRUNCATED" if truncated else "COMPLETE"
    write_json(
        partial / "manifest.json",
        {
            "capture_id": capture_id,
            "capture_status": capture_status,
            "command": command_result.__dict__,
            "streams": {
                "stdout": {"bytes": stdout.retained_bytes, "sha256": stdout.sha256},
                "stderr": {"bytes": stderr.retained_bytes, "sha256": stderr.sha256},
            },
            "event_index": {"events": sequence, "sha256": event_hash.hexdigest()},
            "monotonic_finished_ns": time.monotonic_ns(),
        },
    )
    final = captures_root / capture_id
    os.replace(partial, final)
    try:
        directory_fd = os.open(captures_root, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        directory_fd = None
    if directory_fd is not None:
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return CaptureResult(
        capture_id=capture_id,
        path=final,
        command=command_result,
        capture_status=capture_status,
        stdout_bytes=stdout.retained_bytes,
        stderr_bytes=stderr.retained_bytes,
        stdout_sha256=stdout.sha256,
        stderr_sha256=stderr.sha256,
        event_sha256=event_hash.hexdigest(),
        event_count=sequence,
    )
