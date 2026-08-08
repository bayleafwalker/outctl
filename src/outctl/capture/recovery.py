"""Explicit recovery markers for capture directories not atomically finalized."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from outctl.capture.storage import private_dir


@dataclass(frozen=True)
class RecoveryRecord:
    capture_id: str
    path: Path
    status: str = "INCOMPLETE"


def write_incomplete_manifest(
    path: Path,
    capture_id: str,
    *,
    reason: str,
    signals_sent: tuple[int, ...] = (),
    caller_cancelled: bool | None = None,
    timed_out: bool | None = None,
) -> None:
    """Persist an explicit incomplete state without guessing command completion.

    Partial spools can be left by a wrapper crash, or deliberately retained when
    this coroutine is cancelled.  Neither case establishes the child's final
    command status, so that status remains explicitly unknown.
    """
    manifest = path / "manifest.json"
    if not manifest.exists():
        with manifest.open("x", encoding="utf-8") as file:
            os.chmod(manifest, 0o600)
            json.dump(
                {
                    "capture_id": capture_id,
                    "capture_status": "INCOMPLETE",
                    "incomplete": True,
                    "command": {
                        "final_status": "UNKNOWN",
                        "exit_code": None,
                        "signal": None,
                    },
                    "termination": {
                        "reason": reason,
                        "caller_cancelled": caller_cancelled,
                        "timed_out": timed_out,
                        "signals_sent": list(signals_sent),
                    },
                },
                file,
                sort_keys=True,
                separators=(",", ":"),
            )
            file.write("\n")

    marker = path / "recovery.json"
    if not marker.exists():
        with marker.open("x", encoding="utf-8") as file:
            os.chmod(marker, 0o600)
            json.dump(
                {
                    "capture_status": "INCOMPLETE",
                    "incomplete": True,
                    "reason": reason,
                },
                file,
                sort_keys=True,
                separators=(",", ":"),
            )
            file.write("\n")


def recover_partials(root: Path) -> list[RecoveryRecord]:
    """Mark each abandoned partial spool as incomplete; never rerun a command."""
    partial_root = root / "partial"
    if not partial_root.exists():
        return []
    private_dir(partial_root)
    records: list[RecoveryRecord] = []
    for path in sorted(partial_root.glob("*.partial")):
        if not path.is_dir():
            continue
        write_incomplete_manifest(
            path,
            path.stem,
            reason="WRAPPER_INTERRUPTED_OR_CRASHED",
        )
        records.append(RecoveryRecord(capture_id=path.stem, path=path))
    return records
