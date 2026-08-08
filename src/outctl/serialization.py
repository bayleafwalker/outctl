"""Canonical, deterministic JSON serialization for outctl contracts.

The canonical form is used for stable digests and reproducible artifacts:

- UTF-8 encoded text;
- no insignificant whitespace;
- object keys sorted lexicographically;
- no ASCII escapes for Unicode characters;
- ``None`` values omitted.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _drop_none(value: Any) -> Any:
    """Recursively drop ``None`` values so they do not affect digests."""
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value]
    return value


def canonical_json_bytes(data: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for ``data``.

    The output is stable across equivalent object contents regardless of
    insertion order or equivalent YAML spellings.
    """
    cleaned = _drop_none(data)
    return json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_text(data: Any) -> str:
    """Return the canonical JSON as a ``str``."""
    return canonical_json_bytes(data).decode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(data: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON serialization."""
    return sha256_hex(canonical_json_bytes(data))
