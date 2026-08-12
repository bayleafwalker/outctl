"""Fail-closed Linux sandbox runner for the one extension slow path."""

from __future__ import annotations

import os
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, Final, cast

from outctl.extensions.contracts import ExtensionResult, ExtensionStatus
from outctl.extensions.protocol import (
    ExtensionInvocation,
    ExtensionProtocolError,
    parse_result,
)

MAX_STDERR_BYTES: Final = 4 * 1024
_READ_CHUNK: Final = 16 * 1024


class ExtensionSandboxUnavailable(RuntimeError):
    """Raised when the required root-owned bubblewrap sandbox is unavailable."""


def _failed(invocation: ExtensionInvocation, status: ExtensionStatus, code: str) -> ExtensionResult:
    return ExtensionResult.failed(invocation.request, status, diagnostics=(code,))


def _verified_bwrap(configured: str | Path | None) -> Path:
    candidate = os.fspath(configured) if configured is not None else shutil.which("bwrap")
    if not candidate:
        raise ExtensionSandboxUnavailable("the required extension sandbox is unavailable")
    try:
        path = Path(candidate).resolve(strict=True)
        metadata = path.stat()
    except OSError as exc:
        raise ExtensionSandboxUnavailable("the required extension sandbox is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise ExtensionSandboxUnavailable("the extension sandbox executable is not trusted")
    return path


def _runtime_roots() -> tuple[Path, ...]:
    candidates = [
        Path(sys.prefix),
        Path(sys.base_prefix),
        Path(__file__).parents[2],
    ]
    base_executable = getattr(sys, "_base_executable", None)
    if isinstance(base_executable, str) and len(Path(base_executable).parents) >= 3:
        # uv keeps the interpreter behind a version-stable directory symlink.
        # Bind the containing runtime root so that the venv's absolute symlink
        # remains resolvable inside the mount namespace.
        candidates.append(Path(base_executable).parents[2])
    if Path("/nix/store").is_dir():
        candidates.append(Path("/nix/store"))
    if Path("/lib64").is_dir():
        candidates.append(Path("/lib64"))
    roots: list[Path] = []
    for candidate in candidates:
        try:
            root = candidate.resolve(strict=True)
        except OSError as exc:
            raise ExtensionSandboxUnavailable("an extension runtime root is unavailable") from exc
        if not root.is_dir() or root == Path("/"):
            raise ExtensionSandboxUnavailable("an extension runtime root is unsafe")
        if root not in roots:
            roots.append(root)
    roots.sort(key=lambda path: (len(path.parts), os.fspath(path)))
    return tuple(roots)


def _nix_runtime_environment() -> tuple[str | None, str | None]:
    """Resolve the Nix loader inputs without forwarding arbitrary host paths."""
    loader_value = os.environ.get("NIX_LD")
    library_value = os.environ.get("NIX_LD_LIBRARY_PATH")
    if loader_value is None and library_value is None:
        return None, None
    store = Path("/nix/store")
    try:
        loader = Path(loader_value).resolve(strict=True) if loader_value else None
        libraries = tuple(
            Path(item).resolve(strict=True)
            for item in (library_value or "").split(os.pathsep)
            if item
        )
        loader_metadata = loader.stat() if loader is not None else None
        library_metadata = tuple(path.stat() for path in libraries)
    except OSError as exc:
        raise ExtensionSandboxUnavailable("the Nix extension runtime is unavailable") from exc
    if loader is not None and (
        not loader.is_relative_to(store)
        or loader_metadata is None
        or not stat.S_ISREG(loader_metadata.st_mode)
        or loader_metadata.st_uid != 0
        or loader_metadata.st_mode & 0o022
    ):
        raise ExtensionSandboxUnavailable("the Nix extension runtime is untrusted")
    if any(
        not path.is_relative_to(store)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        for path, metadata in zip(libraries, library_metadata, strict=True)
    ):
        raise ExtensionSandboxUnavailable("the Nix extension runtime is untrusted")
    return (
        os.fspath(loader) if loader is not None else None,
        os.pathsep.join(os.fspath(path) for path in libraries) if libraries else None,
    )


def _sandbox_command(
    bwrap: Path,
    invocation: ExtensionInvocation,
    plugin_roots: tuple[Path, ...],
) -> list[str]:
    roots = _runtime_roots()
    command = [
        os.fspath(bwrap),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "LC_ALL",
        "C.UTF-8",
        "--setenv",
        "PYTHONHASHSEED",
        "0",
    ]
    nix_ld, nix_library_path = _nix_runtime_environment()
    if nix_ld:
        command.extend(("--setenv", "NIX_LD", nix_ld))
    if nix_library_path:
        command.extend(("--setenv", "NIX_LD_LIBRARY_PATH", nix_library_path))
    for root in roots:
        command.extend(("--ro-bind", os.fspath(root), os.fspath(root)))
    command.extend(("--dir", "/extensions"))
    mapped_plugin_roots: list[Path] = []
    for index, root in enumerate(plugin_roots):
        mapped = Path(f"/extensions/{index}")
        command.extend(("--ro-bind", os.fspath(root), os.fspath(mapped)))
        mapped_plugin_roots.append(mapped)
    command.extend(
        (
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/work",
            "--chdir",
            "/work",
            os.fspath(Path(sys.executable)),
            "-I",
            "-m",
            "outctl.extensions.worker",
        )
    )
    for root in mapped_plugin_roots:
        command.extend(("--plugin-root", os.fspath(root)))
    # Force construction here so oversize/invalid requests fail before spawn.
    invocation.to_bytes()
    return command


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _exchange(
    process: subprocess.Popen[bytes],
    body: bytes,
    *,
    deadline: float,
    stdout_limit: int,
) -> tuple[bytes, bytes, bool, bool]:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise RuntimeError("extension subprocess pipes were not created")
    selector = selectors.DefaultSelector()
    for stream in (process.stdin, process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    offset = 0
    stdout = bytearray()
    stderr = bytearray()
    timed_out = False
    overflowed = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_group(process)
                break
            events = selector.select(min(remaining, 0.05))
            if not events and process.poll() is not None:
                # A final nonblocking read observes EOF on all output pipes.
                events = [
                    (key, selectors.EVENT_READ)
                    for key in selector.get_map().values()
                    if key.data != "stdin"
                ]
                if not events:
                    break
            for key, _mask in events:
                stream = cast(BinaryIO, key.fileobj)
                if key.data == "stdin":
                    try:
                        written = os.write(stream.fileno(), body[offset : offset + _READ_CHUNK])
                    except BrokenPipeError:
                        written = 0
                        offset = len(body)
                    offset += written
                    if offset >= len(body):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), _READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                target = stdout if key.data == "stdout" else stderr
                limit = stdout_limit if key.data == "stdout" else MAX_STDERR_BYTES
                target.extend(chunk[: max(0, limit + 1 - len(target))])
                if len(target) > limit:
                    overflowed = True
                    _kill_group(process)
                    break
            if overflowed:
                break
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    if timed_out or overflowed:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
    else:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            _kill_group(process)
            process.wait(timeout=1)
        else:
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_group(process)
                process.wait(timeout=1)
    return bytes(stdout), bytes(stderr), timed_out, overflowed


def _plugin_root(value: str | Path) -> Path:
    try:
        root = Path(value).resolve(strict=True)
    except OSError as exc:
        raise ExtensionSandboxUnavailable("an extension distribution root is unavailable") from exc
    forbidden_parts = {"spool", ".spool", "outctl-spool", "_artifacts"}
    if (
        not root.is_dir()
        or root == Path("/")
        or (root / ".git").exists()
        or any(part.casefold() in forbidden_parts for part in root.parts)
    ):
        raise ExtensionSandboxUnavailable("an extension distribution root is unsafe")
    if not any(path.is_dir() for path in root.glob("*.dist-info")):
        raise ExtensionSandboxUnavailable(
            "an extension plugin root must be an installed distribution root"
        )
    return root


def invoke_extension(
    invocation: ExtensionInvocation,
    *,
    plugin_roots: Iterable[str | Path],
    bwrap_path: str | Path | None = None,
) -> ExtensionResult:
    """Run one pinned extension; never falls back to an in-process call."""
    roots = tuple(_plugin_root(root) for root in plugin_roots)
    if not roots:
        raise ExtensionSandboxUnavailable("at least one explicit plugin root is required")
    bwrap = _verified_bwrap(bwrap_path)
    body = invocation.to_bytes()
    command = _sandbox_command(bwrap, invocation, roots)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise ExtensionSandboxUnavailable("the extension sandbox could not start") from exc
    deadline = time.monotonic() + invocation.request.context.deadline_ms / 1_000
    stdout, _stderr, timed_out, overflowed = _exchange(
        process,
        body,
        deadline=deadline,
        stdout_limit=invocation.request.max_result_bytes,
    )
    if timed_out:
        return _failed(invocation, ExtensionStatus.TIMED_OUT, "extension-deadline")
    if overflowed:
        return _failed(invocation, ExtensionStatus.MALFORMED, "extension-output-overflow")
    if process.returncode != 0:
        return _failed(invocation, ExtensionStatus.FAILED, "extension-worker-failed")
    try:
        return parse_result(stdout, invocation)
    except ExtensionProtocolError:
        return _failed(invocation, ExtensionStatus.MALFORMED, "extension-result-malformed")


__all__ = [
    "ExtensionSandboxUnavailable",
    "MAX_STDERR_BYTES",
    "invoke_extension",
]
