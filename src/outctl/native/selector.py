"""Explicit W3 engine selection with a Python-reference rollback default."""

from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class EngineChoice(StrEnum):
    PYTHON_REFERENCE = "python-reference"
    RUST_NATIVE = "rust-native"


class NativeEngineUnavailable(RuntimeError):
    """Raised when native was explicitly selected but cannot be resolved."""


@dataclass(frozen=True)
class EngineSelection:
    choice: EngineChoice
    executable: Path | None
    reason: str


def select_engine(
    configured: str | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    native_executable: Path | None = None,
) -> EngineSelection:
    """Select one engine without importing or silently replacing either engine.

    Python remains the migration default. The native path is opt-in until the
    later rollout gate, and the existing bypass flags always select the
    reference boundary without capture-state migration.
    """
    values = os.environ if environment is None else environment
    if values.get("OUTCTL_ENABLED") == "0" or values.get("OUTCTL_MODE") == "bypass":
        return EngineSelection(
            EngineChoice.PYTHON_REFERENCE,
            None,
            "rollback/bypass selected",
        )
    requested = configured or values.get("OUTCTL_ENGINE", EngineChoice.PYTHON_REFERENCE.value)
    aliases = {
        "python": EngineChoice.PYTHON_REFERENCE,
        "python-reference": EngineChoice.PYTHON_REFERENCE,
        "rust": EngineChoice.RUST_NATIVE,
        "rust-native": EngineChoice.RUST_NATIVE,
    }
    try:
        choice = aliases[requested]
    except KeyError as exc:
        raise ValueError(f"unsupported OUTCTL_ENGINE value: {requested!r}") from exc
    if choice is EngineChoice.PYTHON_REFERENCE:
        return EngineSelection(choice, None, "Python compatibility reference selected")
    candidate = native_executable
    if candidate is None and (configured_path := values.get("OUTCTL_NATIVE_BINARY")):
        candidate = Path(configured_path)
    if candidate is None and (resolved := shutil.which("outctl-native")):
        candidate = Path(resolved)
    if candidate is None or not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise NativeEngineUnavailable(
            "rust-native was explicitly selected but outctl-native is unavailable"
        )
    return EngineSelection(choice, candidate.resolve(), "explicit native selection")


__all__ = [
    "EngineChoice",
    "EngineSelection",
    "NativeEngineUnavailable",
    "select_engine",
]
