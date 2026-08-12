"""Side-effect-free discovery and exact pinning for Python extensions.

Discovery reads installed distribution metadata and files.  It deliberately
never calls :meth:`importlib.metadata.EntryPoint.load`; extension code is only
loaded by the isolated worker.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

ENTRY_POINT_GROUP: Final = "outctl.extensions.v1"
EXTENSION_API_VERSION: Final = "1"
MAX_DISTRIBUTION_FILES: Final = 4_096
MAX_FINGERPRINT_BYTES: Final = 32 * 1024 * 1024
_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_DIST_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}$")
_TARGET_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(?::[A-Za-z_][A-Za-z0-9_.]*)?$")


class ExtensionDiscoveryError(ValueError):
    """Raised when installed metadata cannot be safely and uniquely pinned."""


@dataclass(frozen=True)
class ExtensionPin:
    extension_id: str
    distribution: str
    version: str
    target: str
    fingerprint: str
    api_version: str = EXTENSION_API_VERSION

    def __post_init__(self) -> None:
        if _IDENTIFIER_RE.fullmatch(self.extension_id) is None:
            raise ExtensionDiscoveryError("extension id is not portable")
        if _DIST_RE.fullmatch(self.distribution) is None:
            raise ExtensionDiscoveryError("extension distribution name is not portable")
        if _VERSION_RE.fullmatch(self.version) is None:
            raise ExtensionDiscoveryError("extension distribution version is not portable")
        if len(self.target) > 512 or _TARGET_RE.fullmatch(self.target) is None:
            raise ExtensionDiscoveryError("extension entry-point target is unsafe")
        if re.fullmatch(r"sha256:[a-f0-9]{64}", self.fingerprint) is None:
            raise ExtensionDiscoveryError("extension fingerprint must be sha256:<hex>")
        if self.api_version != EXTENSION_API_VERSION:
            raise ExtensionDiscoveryError("extension API version is unsupported")

    def to_dict(self) -> dict[str, str]:
        return {
            "extension_id": self.extension_id,
            "distribution": self.distribution,
            "version": self.version,
            "target": self.target,
            "fingerprint": self.fingerprint,
            "api_version": self.api_version,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExtensionPin:
        if not isinstance(value, dict) or set(value) != {
            "extension_id",
            "distribution",
            "version",
            "target",
            "fingerprint",
            "api_version",
        }:
            raise ExtensionDiscoveryError("extension pin has an invalid shape")
        if not all(isinstance(item, str) for item in value.values()):
            raise ExtensionDiscoveryError("extension pin fields must be strings")
        return cls(
            value["extension_id"],
            value["distribution"],
            value["version"],
            value["target"],
            value["fingerprint"],
            value["api_version"],
        )


@dataclass(frozen=True)
class DiscoveredExtension:
    pin: ExtensionPin
    metadata_root: Path
    _entry_point: importlib.metadata.EntryPoint = field(repr=False, compare=False)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _distribution_name(distribution: importlib.metadata.Distribution) -> str:
    name = distribution.metadata.get("Name")
    if not isinstance(name, str) or _DIST_RE.fullmatch(name) is None:
        raise ExtensionDiscoveryError("extension distribution has no safe Name metadata")
    return name


def _distribution_fingerprint(distribution: importlib.metadata.Distribution) -> str:
    files = distribution.files
    if files is None or len(files) > MAX_DISTRIBUTION_FILES:
        raise ExtensionDiscoveryError("extension distribution has no bounded file manifest")
    digest = hashlib.sha256()
    digest.update(
        _canonical_bytes(
            {
                "name": _distribution_name(distribution),
                "version": distribution.version,
            }
        )
    )
    consumed = 0
    observed = 0
    try:
        root = Path(str(distribution.locate_file(""))).resolve(strict=True)
    except OSError as exc:
        raise ExtensionDiscoveryError("extension distribution root cannot be pinned") from exc
    for relative in sorted(files, key=lambda item: str(item)):
        name = str(relative).replace(os.sep, "/")
        if not name or name.startswith("/") or "\x00" in name or ".." in Path(name).parts:
            raise ExtensionDiscoveryError("extension distribution file manifest is unsafe")
        located = Path(str(distribution.locate_file(relative)))
        try:
            if located.is_symlink():
                raise ExtensionDiscoveryError("extension distribution contains a symlink")
            path = located.resolve(strict=True)
        except OSError as exc:
            raise ExtensionDiscoveryError("extension distribution file cannot be pinned") from exc
        if not path.is_relative_to(root):
            raise ExtensionDiscoveryError("extension distribution file escapes its root")
        try:
            if not path.is_file():
                raise ExtensionDiscoveryError("extension distribution contains an unsafe file")
            size = path.stat().st_size
        except OSError as exc:
            raise ExtensionDiscoveryError("extension distribution file cannot be pinned") from exc
        if size < 0 or consumed + size > MAX_FINGERPRINT_BYTES:
            raise ExtensionDiscoveryError("extension distribution exceeds fingerprint bounds")
        consumed += size
        observed += 1
        digest.update(_canonical_bytes({"path": name, "size": size}))
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(65_536):
                    digest.update(chunk)
        except OSError as exc:
            raise ExtensionDiscoveryError("extension distribution file cannot be hashed") from exc
    if observed == 0:
        raise ExtensionDiscoveryError("extension distribution has an empty file manifest")
    return "sha256:" + digest.hexdigest()


def _iter_distributions(
    paths: Sequence[str | Path] | None,
) -> Iterable[importlib.metadata.Distribution]:
    if paths is None:
        return importlib.metadata.distributions()
    normalized = [os.fspath(Path(path).resolve(strict=True)) for path in paths]
    return importlib.metadata.distributions(path=normalized)


def discover_extensions(
    paths: Sequence[str | Path] | None = None,
) -> tuple[DiscoveredExtension, ...]:
    """Discover v1 metadata deterministically without importing plugin code."""
    discovered: list[DiscoveredExtension] = []
    for distribution in _iter_distributions(paths):
        matches = [entry for entry in distribution.entry_points if entry.group == ENTRY_POINT_GROUP]
        if not matches:
            continue
        name = _distribution_name(distribution)
        version = distribution.version
        if not isinstance(version, str):
            raise ExtensionDiscoveryError("extension distribution has no version")
        fingerprint = _distribution_fingerprint(distribution)
        try:
            root = Path(str(distribution.locate_file(""))).resolve(strict=True)
        except OSError as exc:
            raise ExtensionDiscoveryError("extension distribution root cannot be resolved") from exc
        for entry in matches:
            pin = ExtensionPin(entry.name, name, version, entry.value, fingerprint)
            discovered.append(DiscoveredExtension(pin, root, entry))
    discovered.sort(
        key=lambda item: (
            item.pin.extension_id,
            item.pin.distribution.casefold(),
            item.pin.version,
            item.pin.target,
            item.pin.fingerprint,
        )
    )
    ids: set[str] = set()
    for item in discovered:
        if item.pin.extension_id in ids:
            raise ExtensionDiscoveryError("extension ids must be globally unique")
        ids.add(item.pin.extension_id)
    return tuple(discovered)


def select_extension(
    discovered: Iterable[DiscoveredExtension], pin: ExtensionPin
) -> DiscoveredExtension:
    """Return the one exact installed match for an explicit caller-owned pin."""
    matches = [item for item in discovered if item.pin == pin]
    if len(matches) != 1:
        raise ExtensionDiscoveryError("pinned extension is absent, ambiguous, or changed")
    return matches[0]


__all__ = [
    "DiscoveredExtension",
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "ExtensionDiscoveryError",
    "ExtensionPin",
    "discover_extensions",
    "select_extension",
]
