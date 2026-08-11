"""Typed and bounded extension request/result interfaces.

The result body is canonical JSON data, never raw output or an opaque command
result.  A result that cannot fit its caller-provided byte budget is rejected
instead of being silently cut into invalid or misleading JSON.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

DEFAULT_MAX_RESULT_BYTES: Final = 64 * 1024
MAX_EXTENSION_ID_LENGTH: Final = 160
_FORBIDDEN_KEYS: Final = frozenset(
    {
        "authorize_execution",
        "can_authorize_execution",
        "can_retry",
        "command",
        "credential",
        "environment",
        "lifecycle",
        "raw_output",
        "secret",
        "spool_path",
        "stdin",
    }
)


class ExtensionResultTooLarge(ValueError):
    """Raised when an extension result exceeds its negotiated JSON budget."""


class ExtensionKind(StrEnum):
    FACTS = "facts"
    POLICY_CANDIDATE = "policy-candidate"
    PROJECTION_CANDIDATE = "projection-candidate"
    SANITIZER = "sanitizer"


class ExtensionStatus(StrEnum):
    ACCEPTED = "accepted"
    EMPTY = "empty"
    REJECTED = "rejected"
    TIMED_OUT = "timed-out"
    FAILED = "failed"
    MALFORMED = "malformed"


def _validate_json(value: object, path: str = "$") -> JsonValue:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"extension JSON contains a non-finite number at {path}")
        return value
    if isinstance(value, list):
        return [_validate_json(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"extension JSON key is not a string at {path}")
            if key.casefold() in _FORBIDDEN_KEYS:
                raise ValueError(f"extension result field is outside the extension boundary: {key}")
            result[key] = _validate_json(child, f"{path}.{key}")
        return result
    raise TypeError(f"extension JSON value at {path} is not JSON-compatible")


def _canonical_bytes(value: Mapping[str, JsonValue]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _result_bytes(
    extension_id: str,
    status: ExtensionStatus,
    kind: ExtensionKind | None,
    payload: Mapping[str, JsonValue],
    diagnostics: tuple[str, ...],
) -> bytes:
    """Encode the complete result, including its size metadata."""
    document: dict[str, JsonValue] = {
        "extension_id": extension_id,
        "status": status.value,
        "kind": kind.value if kind is not None else None,
        "payload": dict(payload),
        "diagnostics": list(diagnostics),
    }
    size = len(_canonical_bytes(document))
    while True:
        with_size = {**document, "encoded_bytes": size}
        observed = len(_canonical_bytes(with_size))
        if observed == size:
            return _canonical_bytes(with_size)
        size = observed


@dataclass(frozen=True)
class ExtensionContext:
    """Non-sensitive commissioning context made available to an extension."""

    workspace_id: str
    session_id: str
    policy_snapshot_id: str
    deadline_ms: int

    def __post_init__(self) -> None:
        if not self.workspace_id or not self.session_id or not self.policy_snapshot_id:
            raise ValueError("extension context identifiers must be non-empty")
        if self.deadline_ms < 1:
            raise ValueError("extension deadline_ms must be positive")


@dataclass(frozen=True)
class ExtensionRequest:
    """A bounded, JSON-only input for a commissioning/slow-path extension."""

    extension_id: str
    context: ExtensionContext
    input: Mapping[str, JsonValue] = field(default_factory=dict)
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES

    def __post_init__(self) -> None:
        if not self.extension_id or len(self.extension_id) > MAX_EXTENSION_ID_LENGTH:
            raise ValueError("extension_id must be 1..160 characters")
        if self.max_result_bytes < 1:
            raise ValueError("max_result_bytes must be positive")
        checked = _validate_json(dict(self.input))
        if not isinstance(checked, dict):
            raise TypeError("extension input must be a JSON object")
        object.__setattr__(self, "input", checked)


@dataclass(frozen=True)
class ExtensionResult:
    """A bounded extension contribution that cannot widen engine authority."""

    extension_id: str
    status: ExtensionStatus
    kind: ExtensionKind | None = None
    payload: Mapping[str, JsonValue] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()
    max_bytes: int = DEFAULT_MAX_RESULT_BYTES

    def __post_init__(self) -> None:
        if not self.extension_id:
            raise ValueError("extension_id must be non-empty")
        if self.max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        checked = _validate_json(dict(self.payload))
        if not isinstance(checked, dict):
            raise TypeError("extension payload must be a JSON object")
        if self.status is ExtensionStatus.ACCEPTED and self.kind is None:
            raise ValueError("accepted extension results require a contribution kind")
        if self.status is not ExtensionStatus.ACCEPTED and self.kind is not None:
            raise ValueError("non-accepted extension results cannot carry a contribution kind")
        if self.status is not ExtensionStatus.ACCEPTED and checked:
            raise ValueError("non-accepted extension results cannot carry a payload")
        if any(not isinstance(item, str) or len(item) > 512 for item in self.diagnostics):
            raise ValueError("extension diagnostics must be short strings")
        encoded_size = len(
            _result_bytes(self.extension_id, self.status, self.kind, checked, self.diagnostics)
        )
        if encoded_size > self.max_bytes:
            raise ExtensionResultTooLarge(
                f"extension result is {encoded_size} bytes; limit is {self.max_bytes}"
            )
        object.__setattr__(self, "payload", checked)

    @property
    def encoded_bytes(self) -> int:
        return len(
            _result_bytes(self.extension_id, self.status, self.kind, self.payload, self.diagnostics)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension_id,
            "status": self.status.value,
            "kind": self.kind.value if self.kind is not None else None,
            "payload": dict(self.payload),
            "diagnostics": list(self.diagnostics),
            "encoded_bytes": self.encoded_bytes,
        }

    @classmethod
    def accepted(
        cls,
        request: ExtensionRequest,
        kind: ExtensionKind,
        payload: Mapping[str, JsonValue],
        *,
        diagnostics: tuple[str, ...] = (),
    ) -> ExtensionResult:
        return cls(
            request.extension_id,
            ExtensionStatus.ACCEPTED,
            kind,
            payload,
            diagnostics,
            request.max_result_bytes,
        )

    @classmethod
    def failed(
        cls,
        request: ExtensionRequest,
        status: ExtensionStatus = ExtensionStatus.FAILED,
        *,
        diagnostics: tuple[str, ...] = (),
    ) -> ExtensionResult:
        if status is ExtensionStatus.ACCEPTED or status is ExtensionStatus.EMPTY:
            raise ValueError("failed() requires a failure status")
        return cls(
            request.extension_id,
            status,
            diagnostics=diagnostics,
            max_bytes=request.max_result_bytes,
        )


class ExtensionProtocol(Protocol):
    """Minimal extension implementation surface; no execution authority."""

    extension_id: str

    def evaluate(self, request: ExtensionRequest) -> ExtensionResult:
        """Return one bounded, untrusted contribution or an explicit failure."""


__all__ = [
    "DEFAULT_MAX_RESULT_BYTES",
    "ExtensionContext",
    "ExtensionKind",
    "ExtensionProtocol",
    "ExtensionRequest",
    "ExtensionResult",
    "ExtensionResultTooLarge",
    "ExtensionStatus",
    "JsonValue",
]
