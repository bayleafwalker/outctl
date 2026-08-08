"""Read-only, bounded retrieval of locally captured command output.

This module intentionally has no dependency on the command runner.  It only
reads an existing spool and treats malformed, partial, and changed evidence as
explicit states; it never attempts to recreate a capture by executing a
command.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

_STREAMS = frozenset(("stdout", "stderr"))
_CHUNK_BYTES = 64 * 1024
_DEFAULT_MAX_BYTES = 64 * 1024
_MAX_CONTEXT_BYTES = 4 * 1024
_MAX_MATCHES = 100


class RetrievalStatus(StrEnum):
    """State of a read-only retrieval attempt."""

    AVAILABLE = "AVAILABLE"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"
    TAMPERED = "TAMPERED"
    DENIED = "DENIED"


@dataclass(frozen=True)
class InspectionResult:
    status: RetrievalStatus
    capture_id: str
    capture_status: str | None = None
    manifest: Mapping[str, object] | None = None
    detail: str | None = None


@dataclass(frozen=True)
class SliceResult:
    status: RetrievalStatus
    capture_id: str
    stream: str
    start: int
    end: int
    data: bytes = b""
    detail: str | None = None


@dataclass(frozen=True)
class TailResult:
    status: RetrievalStatus
    capture_id: str
    stream: str
    data: bytes = b""
    truncated: bool = False
    detail: str | None = None


@dataclass(frozen=True)
class SearchMatch:
    """A match and a byte-bounded window around it."""

    start: int
    end: int
    context: bytes


@dataclass(frozen=True)
class SearchResult:
    status: RetrievalStatus
    capture_id: str
    stream: str
    matches: tuple[SearchMatch, ...] = ()
    limited: bool = False
    detail: str | None = None


@dataclass(frozen=True)
class DigestCheck:
    artifact: Literal["stdout", "stderr", "events"]
    expected: str | None
    observed: str | None
    matches: bool


@dataclass(frozen=True)
class VerificationResult:
    status: RetrievalStatus
    capture_id: str
    checks: tuple[DigestCheck, ...] = ()
    detail: str | None = None


@dataclass(frozen=True)
class _ResolvedCapture:
    status: RetrievalStatus
    capture_id: str
    path: Path | None = None
    detail: str | None = None


def _valid_capture_id(capture_id: str) -> bool:
    return (
        bool(capture_id)
        and capture_id not in {".", ".."}
        and "/" not in capture_id
        and "\\" not in capture_id
        and Path(capture_id).name == capture_id
    )


def _safe_directory(path: Path) -> bool:
    """Return whether ``path`` is a real directory, never a symlink."""
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return False
    return stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)


def _entry_exists(path: Path) -> bool:
    """Check existence without following a final symlink."""
    try:
        os.lstat(path)
    except OSError:
        return False
    return True


def _resolve_capture(spool_root: Path, capture_id: str) -> _ResolvedCapture:
    if not _valid_capture_id(capture_id):
        return _ResolvedCapture(RetrievalStatus.DENIED, capture_id, detail="invalid capture id")
    if not _safe_directory(spool_root):
        status = (
            RetrievalStatus.DENIED if _entry_exists(spool_root) else RetrievalStatus.UNAVAILABLE
        )
        return _ResolvedCapture(status, capture_id, detail="spool unavailable or unsafe")

    for group, status in (
        ("captures", RetrievalStatus.AVAILABLE),
        ("partial", RetrievalStatus.INCOMPLETE),
    ):
        group_path = spool_root / group
        if _entry_exists(group_path) and not _safe_directory(group_path):
            return _ResolvedCapture(
                RetrievalStatus.DENIED, capture_id, detail="symlinked spool path"
            )
        name = capture_id if group == "captures" else f"{capture_id}.partial"
        candidate = group_path / name
        if not _entry_exists(candidate):
            continue
        if not _safe_directory(candidate):
            return _ResolvedCapture(
                RetrievalStatus.DENIED, capture_id, detail="symlinked capture path"
            )
        return _ResolvedCapture(status, capture_id, path=candidate)
    return _ResolvedCapture(RetrievalStatus.UNAVAILABLE, capture_id, detail="capture unavailable")


def _safe_file(path: Path) -> bool:
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def _load_manifest(
    resolved: _ResolvedCapture,
) -> tuple[RetrievalStatus, Mapping[str, object] | None, str | None]:
    if resolved.status is not RetrievalStatus.AVAILABLE:
        return resolved.status, None, resolved.detail
    assert resolved.path is not None
    path = resolved.path / "manifest.json"
    if not _safe_file(path):
        return RetrievalStatus.INCOMPLETE, None, "finalized capture has no safe manifest"
    try:
        with path.open("rb") as file:
            parsed = json.load(file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return RetrievalStatus.TAMPERED, None, "manifest is unreadable"
    if not isinstance(parsed, dict):
        return RetrievalStatus.TAMPERED, None, "manifest is not an object"
    return RetrievalStatus.AVAILABLE, parsed, None


def _authorize_workspace(
    manifest: Mapping[str, object], expected_workspace_id: str | None
) -> tuple[RetrievalStatus, str | None]:
    """Authorize a resolved capture against its manifest workspace identity."""
    if expected_workspace_id is None:
        return RetrievalStatus.AVAILABLE, None
    source = manifest.get("source")
    workspace_id = source.get("workspace_id") if isinstance(source, dict) else None
    if not isinstance(workspace_id, str) or workspace_id != expected_workspace_id:
        return RetrievalStatus.DENIED, "workspace authorization denied"
    return RetrievalStatus.AVAILABLE, None


def _authorized_manifest(
    resolved: _ResolvedCapture, expected_workspace_id: str | None
) -> tuple[RetrievalStatus, Mapping[str, object] | None, str | None]:
    status, manifest, detail = _load_manifest(resolved)
    if manifest is None:
        return status, None, detail
    authorization, authorization_detail = _authorize_workspace(manifest, expected_workspace_id)
    if authorization is not RetrievalStatus.AVAILABLE:
        return authorization, None, authorization_detail
    return status, manifest, detail


def _stream_path(
    resolved: _ResolvedCapture, stream: str, expected_workspace_id: str | None
) -> tuple[RetrievalStatus, Path | None, str | None]:
    if stream not in _STREAMS:
        raise ValueError("stream must be 'stdout' or 'stderr'")
    if resolved.status is not RetrievalStatus.AVAILABLE:
        return resolved.status, None, resolved.detail
    status, _manifest, detail = _authorized_manifest(resolved, expected_workspace_id)
    if status is not RetrievalStatus.AVAILABLE:
        return status, None, detail
    assert resolved.path is not None
    path = resolved.path / f"{stream}.raw"
    if not _safe_file(path):
        return RetrievalStatus.TAMPERED, None, "stream is missing or unsafe"
    return RetrievalStatus.AVAILABLE, path, None


def _read_range(path: Path, start: int, end: int) -> bytes:
    with path.open("rb") as file:
        file.seek(start)
        return file.read(end - start)


def inspect_capture(
    spool_root: Path, capture_id: str, *, expected_workspace_id: str | None = None
) -> InspectionResult:
    """Read a capture manifest without opening raw streams."""
    resolved = _resolve_capture(spool_root, capture_id)
    status, manifest, detail = _authorized_manifest(resolved, expected_workspace_id)
    capture_status = manifest.get("capture_status") if manifest is not None else None
    if capture_status is not None and not isinstance(capture_status, str):
        return InspectionResult(
            RetrievalStatus.TAMPERED, capture_id, detail="invalid capture status"
        )
    return InspectionResult(status, capture_id, capture_status, manifest, detail)


def slice_stream(
    spool_root: Path,
    capture_id: str,
    stream: str,
    start: int,
    end: int,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    expected_workspace_id: str | None = None,
) -> SliceResult:
    """Return one bounded half-open byte range from an existing stream."""
    if start < 0 or end < start:
        raise ValueError("slice range must be a non-negative half-open range")
    if max_bytes <= 0 or end - start > max_bytes:
        raise ValueError("slice range exceeds max_bytes")
    resolved = _resolve_capture(spool_root, capture_id)
    status, path, detail = _stream_path(resolved, stream, expected_workspace_id)
    if path is None:
        return SliceResult(status, capture_id, stream, start, end, detail=detail)
    try:
        size = path.stat().st_size
        actual_end = min(end, size)
        data = _read_range(path, start, actual_end) if start < actual_end else b""
    except OSError:
        return SliceResult(
            RetrievalStatus.TAMPERED, capture_id, stream, start, end, detail="stream unreadable"
        )
    return SliceResult(RetrievalStatus.AVAILABLE, capture_id, stream, start, actual_end, data)


def tail_stream(
    spool_root: Path,
    capture_id: str,
    stream: str,
    *,
    lines: int | None = None,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    expected_workspace_id: str | None = None,
) -> TailResult:
    """Return a byte-bounded suffix, optionally selecting its final lines."""
    if lines is not None and lines < 0:
        raise ValueError("lines must be non-negative")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    resolved = _resolve_capture(spool_root, capture_id)
    status, path, detail = _stream_path(resolved, stream, expected_workspace_id)
    if path is None:
        return TailResult(status, capture_id, stream, detail=detail)
    try:
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        data = _read_range(path, start, size)
    except OSError:
        return TailResult(RetrievalStatus.TAMPERED, capture_id, stream, detail="stream unreadable")
    truncated = start != 0
    if lines is not None:
        data = b"".join(data.splitlines(keepends=True)[-lines:]) if lines else b""
    return TailResult(RetrievalStatus.AVAILABLE, capture_id, stream, data, truncated)


def _pattern_bytes(pattern: bytes | str) -> bytes:
    value = pattern.encode("utf-8") if isinstance(pattern, str) else bytes(pattern)
    if not value:
        raise ValueError("search pattern must not be empty")
    return value


def search_stream(
    spool_root: Path,
    capture_id: str,
    stream: str,
    pattern: bytes | str,
    *,
    regex: bool = False,
    context_bytes: int = 80,
    max_matches: int = 100,
    expected_workspace_id: str | None = None,
) -> SearchResult:
    """Search an existing stream, returning only byte-bounded match windows.

    Regex matching is chunked with a fixed overlap.  This supports ordinary
    bounded diagnostics while ensuring a pathological stream never becomes a
    complete in-memory buffer.
    """
    needle = _pattern_bytes(pattern)
    if not 0 <= context_bytes <= _MAX_CONTEXT_BYTES:
        raise ValueError(f"context_bytes must be between 0 and {_MAX_CONTEXT_BYTES}")
    if not 0 < max_matches <= _MAX_MATCHES:
        raise ValueError(f"max_matches must be between 1 and {_MAX_MATCHES}")
    try:
        matcher = re.compile(needle) if regex else None
    except re.error as error:
        raise ValueError(f"invalid regex: {error}") from error
    resolved = _resolve_capture(spool_root, capture_id)
    status, path, detail = _stream_path(resolved, stream, expected_workspace_id)
    if path is None:
        return SearchResult(status, capture_id, stream, detail=detail)
    try:
        size = path.stat().st_size
        matches: list[SearchMatch] = []
        overlap = b""
        offset = 0
        with path.open("rb") as file:
            while chunk := file.read(_CHUNK_BYTES):
                window = overlap + chunk
                window_start = offset - len(overlap)
                if matcher is not None:
                    positions = [item.span() for item in matcher.finditer(window)]
                else:
                    positions = _find_all(window, needle)
                for local_start, local_end in positions:
                    start, end = window_start + local_start, window_start + local_end
                    if end <= offset or start == end:
                        continue
                    context = _read_range(
                        path, max(0, start - context_bytes), min(size, end + context_bytes)
                    )
                    matches.append(SearchMatch(start, end, context))
                    if len(matches) == max_matches:
                        return SearchResult(
                            RetrievalStatus.AVAILABLE, capture_id, stream, tuple(matches), True
                        )
                overlap = window[-_CHUNK_BYTES:]
                offset += len(chunk)
    except OSError:
        return SearchResult(
            RetrievalStatus.TAMPERED, capture_id, stream, detail="stream unreadable"
        )
    return SearchResult(RetrievalStatus.AVAILABLE, capture_id, stream, tuple(matches))


def _find_all(data: bytes, needle: bytes) -> list[tuple[int, int]]:
    matches: list[tuple[int, int]] = []
    start = 0
    while (found := data.find(needle, start)) != -1:
        matches.append((found, found + len(needle)))
        start = found + 1
    return matches


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def verify_capture(
    spool_root: Path, capture_id: str, *, expected_workspace_id: str | None = None
) -> VerificationResult:
    """Verify finalized stream and event-index digests against its manifest."""
    resolved = _resolve_capture(spool_root, capture_id)
    status, manifest, detail = _authorized_manifest(resolved, expected_workspace_id)
    if manifest is None:
        return VerificationResult(status, capture_id, detail=detail)
    streams = manifest.get("streams")
    event_index = manifest.get("event_index")
    if not isinstance(streams, dict) or not isinstance(event_index, dict):
        return VerificationResult(
            RetrievalStatus.TAMPERED, capture_id, detail="manifest hashes missing"
        )
    checks: list[DigestCheck] = []
    artifacts: tuple[tuple[Literal["stdout", "stderr", "events"], str, object], ...] = (
        ("stdout", "stdout.raw", _nested_digest(streams, "stdout")),
        ("stderr", "stderr.raw", _nested_digest(streams, "stderr")),
        ("events", "events.ndjson", event_index.get("sha256")),
    )
    assert resolved.path is not None
    for artifact, filename, expected in artifacts:
        path = resolved.path / filename  # manifest implies a finalized capture
        observed: str | None
        try:
            observed = _sha256(path) if _safe_file(path) else None
        except OSError:
            observed = None
        expected_value = expected if isinstance(expected, str) else None
        checks.append(
            DigestCheck(
                artifact,
                expected_value,
                observed,
                expected_value == observed and observed is not None,
            )
        )
    result_status = (
        RetrievalStatus.AVAILABLE
        if all(check.matches for check in checks)
        else RetrievalStatus.TAMPERED
    )
    return VerificationResult(result_status, capture_id, tuple(checks))


def _nested_digest(streams: Mapping[str, object], stream: str) -> object:
    entry = streams.get(stream)
    return entry.get("sha256") if isinstance(entry, dict) else None
