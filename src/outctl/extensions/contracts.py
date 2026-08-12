"""Typed and bounded extension request/result interfaces.

The result body is canonical JSON data, never raw output or an opaque command
result.  A result that cannot fit its caller-provided byte budget is rejected
instead of being silently cut into invalid or misleading JSON.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

DEFAULT_MAX_RESULT_BYTES: Final = 64 * 1024
MAX_RESULT_BYTES: Final = 64 * 1024
MAX_REQUEST_BYTES: Final = 64 * 1024
MAX_DEADLINE_MS: Final = 5_000
MAX_EXTENSION_ID_LENGTH: Final = 160
MAX_JSON_DEPTH: Final = 32
MAX_JSON_ITEMS: Final = 2_048
MAX_JSON_STRING_LENGTH: Final = 32 * 1024
_EXTENSION_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_FORBIDDEN_KEYS: Final = frozenset(
    {
        "authorize_execution",
        "authorization",
        "budget",
        "can_authorize_execution",
        "can_retry",
        "capture_commitment",
        "capture_required",
        "command",
        "commissioned",
        "credential",
        "disclosure",
        "durability",
        "environment",
        "execution_authorized",
        "execution_authority",
        "lifecycle",
        "limits",
        "persistence",
        "raw_output",
        "redaction",
        "redaction_required",
        "secret",
        "spool_path",
        "stdin",
        "trust_domain",
    }
)


class ExtensionResultTooLarge(ValueError):
    """Raised when an extension result exceeds its negotiated JSON budget."""


class ExtensionKind(StrEnum):
    FACTS = "facts"
    POLICY_CANDIDATE = "policy-candidate"
    PROJECTION_CANDIDATE = "projection-candidate"
    SANITIZER = "sanitizer"


class ExtensionPhase(StrEnum):
    COMMISSIONING = "commissioning"
    PROJECTION = "projection"


class ExtensionStatus(StrEnum):
    ACCEPTED = "accepted"
    EMPTY = "empty"
    REJECTED = "rejected"
    TIMED_OUT = "timed-out"
    FAILED = "failed"
    MALFORMED = "malformed"


def _validate_json(
    value: object,
    path: str = "$",
    *,
    depth: int = 0,
    remaining: list[int] | None = None,
) -> JsonValue:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("extension JSON exceeds the nesting limit")
    budget = remaining if remaining is not None else [MAX_JSON_ITEMS]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("extension JSON exceeds the item limit")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > MAX_JSON_STRING_LENGTH:
            raise ValueError(f"extension JSON string is too long at {path}")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"extension JSON contains a non-finite number at {path}")
        return value
    if isinstance(value, list):
        return [
            _validate_json(item, f"{path}[{index}]", depth=depth + 1, remaining=budget)
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"extension JSON key is not a string at {path}")
            if len(key) > 128:
                raise ValueError(f"extension JSON key is too long at {path}")
            normalized_key = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
            if normalized_key in _FORBIDDEN_KEYS:
                raise ValueError(f"extension result field is outside the extension boundary: {key}")
            result[key] = _validate_json(child, f"{path}.{key}", depth=depth + 1, remaining=budget)
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
    policy_snapshot_id: str | None
    deadline_ms: int
    phase: ExtensionPhase = ExtensionPhase.PROJECTION
    commissioning_context_digest: str | None = None
    policy_ref: str | None = None
    policy_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.phase, ExtensionPhase):
            raise ValueError("extension phase is unsupported")
        if not self.workspace_id or not self.session_id:
            raise ValueError("extension context identifiers must be non-empty")
        if len(self.workspace_id) > 256 or len(self.session_id) > 256:
            raise ValueError("extension context identifiers exceed their bounds")
        if (
            isinstance(self.deadline_ms, bool)
            or not isinstance(self.deadline_ms, int)
            or not 1 <= self.deadline_ms <= MAX_DEADLINE_MS
        ):
            raise ValueError("extension deadline_ms is outside the supported bounds")
        digest_re = re.compile(r"^sha256:[a-f0-9]{64}$")
        if self.phase is ExtensionPhase.COMMISSIONING:
            if self.policy_snapshot_id is not None or self.policy_ref is not None:
                raise ValueError("commissioning context cannot claim a policy snapshot")
            if (
                self.commissioning_context_digest is None
                or digest_re.fullmatch(self.commissioning_context_digest) is None
                or self.policy_digest is not None
            ):
                raise ValueError("commissioning context requires its exact context digest")
        else:
            if not self.policy_snapshot_id or self.commissioning_context_digest is not None:
                raise ValueError("projection context requires a policy snapshot id")
            # W2 callers supplied only the snapshot id.  Preserve that public
            # constructor while the v1 IPC layer below requires the full triple.
            if (self.policy_ref is None) != (self.policy_digest is None):
                raise ValueError("projection policy ref and digest must be supplied together")
            if self.policy_digest is not None and digest_re.fullmatch(self.policy_digest) is None:
                raise ValueError("projection policy digest must be sha256:<hex>")


@dataclass(frozen=True)
class ExtensionRequest:
    """A bounded, JSON-only input for a commissioning/slow-path extension."""

    extension_id: str
    context: ExtensionContext
    input: Mapping[str, JsonValue] = field(default_factory=dict)
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES

    def __post_init__(self) -> None:
        if _EXTENSION_ID_RE.fullmatch(self.extension_id) is None:
            raise ValueError("extension_id must be a portable 1..160 character identifier")
        if (
            isinstance(self.max_result_bytes, bool)
            or not isinstance(self.max_result_bytes, int)
            or not 1 <= self.max_result_bytes <= MAX_RESULT_BYTES
        ):
            raise ValueError("max_result_bytes is outside the supported bounds")
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
        if _EXTENSION_ID_RE.fullmatch(self.extension_id) is None:
            raise ValueError("extension_id must be a portable identifier")
        if (
            isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or not 1 <= self.max_bytes <= MAX_RESULT_BYTES
        ):
            raise ValueError("max_bytes is outside the supported bounds")
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
    "MAX_DEADLINE_MS",
    "MAX_REQUEST_BYTES",
    "MAX_RESULT_BYTES",
    "ExtensionContext",
    "ExtensionKind",
    "ExtensionPhase",
    "ExtensionProtocol",
    "ExtensionRequest",
    "ExtensionResult",
    "ExtensionResultTooLarge",
    "ExtensionStatus",
    "JsonValue",
]
