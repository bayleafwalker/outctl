"""Direct-versus-wrapped command comparison helpers.

These helpers operate on result structures (such as ``CommandResultEnvelope``
or plain dicts) and verify that wrapping a command did not alter ordinary
process semantics.  They do not themselves execute commands, so they can be
used in Pass 1 before the capture engine exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ComparisonResult:
    """Outcome of comparing a direct run against a wrapped run."""

    exit_match: bool = False
    signal_match: bool = False
    stdout_match: bool = False
    stderr_match: bool = False
    cwd_match: bool = False
    differences: list[str] = field(default_factory=list)

    @property
    def matches(self) -> bool:
        """True when no meaningful semantic differences were detected."""
        return (
            self.exit_match
            and self.signal_match
            and self.stdout_match
            and self.stderr_match
            and self.cwd_match
            and not self.differences
        )


def _get(data: Any, *keys: str, default: Any = None) -> Any:
    """Safely descend into dicts or dataclasses."""
    current: Any = data
    for key in keys:
        if current is None:
            return default
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            current = getattr(current, key, default)
    return current


def _streams_equal(direct: dict[str, Any], wrapped: dict[str, Any]) -> tuple[bool, bool, list[str]]:
    """Compare stdout/stderr using hashes when available, bytes otherwise."""
    differences: list[str] = []
    out_match = True
    err_match = True

    direct_out_hash = _get(direct, "capture", "stdout_sha256")
    wrapped_out_hash = _get(wrapped, "capture", "stdout_sha256")
    direct_err_hash = _get(direct, "capture", "stderr_sha256")
    wrapped_err_hash = _get(wrapped, "capture", "stderr_sha256")

    if direct_out_hash is not None and wrapped_out_hash is not None:
        out_match = direct_out_hash == wrapped_out_hash
    else:
        out_match = _get(direct, "capture", "stdout_bytes", default=-1) == _get(
            wrapped, "capture", "stdout_bytes", default=-2
        )

    if direct_err_hash is not None and wrapped_err_hash is not None:
        err_match = direct_err_hash == wrapped_err_hash
    else:
        err_match = _get(direct, "capture", "stderr_bytes", default=-1) == _get(
            wrapped, "capture", "stderr_bytes", default=-2
        )

    if not out_match:
        differences.append("stdout bytes/hash differ")
    if not err_match:
        differences.append("stderr bytes/hash differ")

    return out_match, err_match, differences


def compare_direct_wrapped(
    direct: Any,
    wrapped: Any,
    allowed_env_prefixes: tuple[str, ...] = ("OUTCTL_",),
) -> ComparisonResult:
    """Compare a direct command result with a wrapped ``outctl`` result.

    The comparison checks exit code, signal, raw stdout/stderr identity, and
    cwd.  Environment drift is not compared by default because the wrapper is
    permitted to document its own variables (``OUTCTL_*``).  Callers that want
    stricter checks can inspect ``differences``.
    """
    differences: list[str] = []

    direct_exit = _get(direct, "command", "exit_code")
    wrapped_exit = _get(wrapped, "command", "exit_code")
    exit_match = direct_exit == wrapped_exit
    if not exit_match:
        differences.append(f"exit code differs: direct={direct_exit!r} wrapped={wrapped_exit!r}")

    direct_signal = _get(direct, "command", "signal")
    wrapped_signal = _get(wrapped, "command", "signal")
    signal_match = direct_signal == wrapped_signal
    if not signal_match:
        differences.append(
            f"signal differs: direct={direct_signal!r} wrapped={wrapped_signal!r}"
        )

    stdout_match, stderr_match, stream_diffs = _streams_equal(direct, wrapped)
    differences.extend(stream_diffs)

    direct_cwd = _get(direct, "invocation", "cwd")
    wrapped_cwd = _get(wrapped, "invocation", "cwd")
    cwd_match = direct_cwd == wrapped_cwd
    if not cwd_match:
        differences.append(f"cwd differs: direct={direct_cwd!r} wrapped={wrapped_cwd!r}")

    # Note environment comparison: we deliberately do not flag additional
    # OUTCTL_* variables introduced by the wrapper, only value changes to
    # existing variables would matter.  Pass 1 does not execute commands, so
    # this remains a documented hook for future passes.
    env_drift = _compare_env(
        _get(direct, "invocation", "env", default={}),
        _get(wrapped, "invocation", "env", default={}),
        allowed_env_prefixes,
    )
    differences.extend(env_drift)

    return ComparisonResult(
        exit_match=exit_match,
        signal_match=signal_match,
        stdout_match=stdout_match,
        stderr_match=stderr_match,
        cwd_match=cwd_match,
        differences=differences,
    )


def _compare_env(
    direct: dict[str, str],
    wrapped: dict[str, str],
    allowed_prefixes: tuple[str, ...],
) -> list[str]:
    """Return environment differences, ignoring wrapper-added variables."""
    differences: list[str] = []
    direct_keys = set(direct)
    wrapped_keys = set(wrapped)

    for key in direct_keys & wrapped_keys:
        if direct[key] != wrapped[key]:
            differences.append(f"env {key!r} changed value")

    for key in wrapped_keys - direct_keys:
        if not any(key.startswith(prefix) for prefix in allowed_prefixes):
            differences.append(f"env {key!r} added by wrapper")

    return differences


def make_direct_reference(
    argv: list[str],
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    cwd: str = "/tmp",
    host_id: str = "testhost",
    harness: str = "direct",
) -> dict[str, Any]:
    """Build a minimal direct-run reference dict for comparison tests.

    This is a test helper: it does not execute a subprocess.  Future passes
    can populate the same shape from a real direct run.
    """
    import hashlib

    return {
        "invocation": {
            "argv_display": argv,
            "shell": False,
            "cwd": cwd,
            "host_id": host_id,
            "harness": harness,
            "started_at": "2026-08-03T18:00:00Z",
        },
        "command": {
            "started": True,
            "exit_code": exit_code,
            "signal": None,
            "timed_out": False,
            "cancelled": False,
        },
        "capture": {
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        },
    }
