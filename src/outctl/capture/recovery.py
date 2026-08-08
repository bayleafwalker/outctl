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
        marker = path / "recovery.json"
        if not marker.exists():
            with marker.open("x", encoding="utf-8") as file:
                os.chmod(marker, 0o600)
                json.dump({"capture_status": "INCOMPLETE"}, file, sort_keys=True)
                file.write("\n")
        records.append(RecoveryRecord(capture_id=path.stem, path=path))
    return records
