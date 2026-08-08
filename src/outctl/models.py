"""Typed Python models for the checked-in outctl JSON schemas.

These dataclasses mirror the contracts in ``schemas/``.  They intentionally do
not implement capture, projection, or retrieval logic; they only provide typed
access to the existing schema shapes and deterministic round-trips.
"""

from __future__ import annotations

import types
from collections.abc import Mapping
from dataclasses import MISSING, dataclass, fields, is_dataclass
from typing import Any, TypeVar, Union, cast, get_args, get_origin, get_type_hints

T = TypeVar("T")


def _is_optional(hint: Any) -> bool:
    """Return True when ``hint`` is ``X | None`` (or ``Optional[X]``)."""
    origin = get_origin(hint)
    if origin not in (Union, types.UnionType):
        return False
    args = get_args(hint)
    return len(args) == 2 and type(None) in args


def _inner_optional(hint: Any) -> Any:
    """Return the non-None member of an optional hint."""
    args = get_args(hint)
    return args[0] if args[0] is not type(None) else args[1]


def _is_union(hint: Any) -> bool:
    """Return True for any union hint (including ``X | Y | None``)."""
    origin = get_origin(hint)
    return origin in (Union, types.UnionType)


def _to_dict(value: Any) -> Any:
    """Recursively convert dataclass instances to plain dicts.

    ``None`` is omitted for optional fields (those with a default value) but
    preserved for required fields (those without a default) so that schemas
    which require a nullable property still validate.  The ``extra`` field is
    flattened into the parent dict so the resulting structure matches the
    original schema.
    """
    if is_dataclass(value) and not isinstance(value, type):
        result: dict[str, Any] = {}
        for field in fields(value):
            v = getattr(value, field.name)
            if field.name == "extra":
                if isinstance(v, dict):
                    result.update({k: _to_dict(val) for k, val in v.items() if val is not None})
                continue
            if v is None and field.default is not MISSING:
                continue
            result[field.name] = _to_dict(v)
        return result
    if isinstance(value, list):
        return [_to_dict(item) for item in value]
    if isinstance(value, dict):
        return {k: _to_dict(v) for k, v in value.items()}
    return value


def _from_dict[T](cls: type[T], data: Mapping[str, Any]) -> T:
    """Instantiate a dataclass from a dict, handling nested dataclasses.

    Unknown keys are collected into an ``extra`` field if present, otherwise
    they raise ``ValueError``.  This matches schemas with
    ``additionalProperties: true`` while still rejecting stray fields for
    closed schemas.
    """
    if not is_dataclass(cls):
        raise TypeError(f"{cls!r} is not a dataclass")
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    extra: dict[str, Any] = {}
    has_extra = "extra" in hints

    for key, value in data.items():
        if key in hints:
            target = hints[key]
            kwargs[key] = _coerce(target, value)
        elif has_extra:
            extra[key] = value
        else:
            raise ValueError(f"{cls.__name__} does not accept field {key!r}")

    if has_extra:
        kwargs["extra"] = extra or None

    return cls(**kwargs)


def _coerce(hint: Any, value: Any) -> Any:
    """Coerce ``value`` to the type described by ``hint``."""
    if value is None:
        return None

    if hint is Any:
        return value

    origin = get_origin(hint)

    if isinstance(hint, type) and is_dataclass(hint):
        if not isinstance(value, dict):
            raise TypeError(f"expected dict for {hint.__name__}, got {type(value).__name__}")
        return _from_dict(hint, value)

    if origin is list:
        if not isinstance(value, list):
            raise TypeError(f"expected list, got {type(value).__name__}")
        (item_hint,) = get_args(hint)
        return [_coerce(item_hint, item) for item in value]

    if origin is dict:
        if not isinstance(value, dict):
            raise TypeError(f"expected dict, got {type(value).__name__}")
        key_hint, val_hint = get_args(hint)
        return {
            _coerce(key_hint, k): _coerce(val_hint, v)
            for k, v in value.items()
        }

    if _is_optional(hint):
        return _coerce(_inner_optional(hint), value)

    if _is_union(hint):
        args = [a for a in get_args(hint) if a is not type(None)]
        for arg in args:
            try:
                return _coerce(arg, value)
            except (TypeError, ValueError):
                continue
        raise TypeError(f"value {value!r} did not match any member of {hint}")

    if isinstance(hint, type) and isinstance(value, hint):
        return value

    return value


# ---------------------------------------------------------------------------
# OutputPolicy models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OutputPolicyMetadata:
    name: str
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicyCapture:
    required: bool
    backend: str
    maxBytes: int
    onFailure: str
    onQuotaExceeded: str
    rawMode: str | None = None
    rawRetention: str | None = None
    manifestRetention: str | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicyBudget:
    maxEstimatedTokens: int
    maxBytes: int
    maxLines: int
    estimator: str


@dataclass(frozen=True)
class OutputPolicyProjection:
    mode: str
    fullIfUnderBytes: int | None = None
    headLines: int | None = None
    tailLines: int | None = None
    failureContextBefore: int | None = None
    failureContextAfter: int | None = None
    warningContextBefore: int | None = None
    warningContextAfter: int | None = None
    collapseCarriageReturnProgress: bool | None = None
    maxLogicalLineBytes: int | None = None
    includeRetrievalHints: bool | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicyRedaction:
    beforeModel: bool
    beforeLocalRaw: bool
    beforeReplica: bool
    exactSecretSource: str | None = None
    ruleSetRef: str | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicySpec:
    capture: OutputPolicyCapture
    budget: OutputPolicyBudget
    projection: OutputPolicyProjection
    redaction: OutputPolicyRedaction
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicy:
    metadata: OutputPolicyMetadata
    spec: OutputPolicySpec
    apiVersion: str = "vuoro.outctl/v1alpha1"
    kind: str = "OutputPolicy"
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OutputPolicy:
        return _from_dict(cls, data)


# ---------------------------------------------------------------------------
# OutputPolicySet models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OutputPolicySetMetadata:
    name: str
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicySetDefaults:
    policy: str
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))


@dataclass(frozen=True)
class OutputPolicySetInlinePolicy:
    extends: str | None = None
    capture: dict[str, Any] | None = None
    budget: dict[str, Any] | None = None
    projection: dict[str, Any] | None = None
    redaction: dict[str, Any] | None = None
    security: dict[str, Any] | None = None
    retention: dict[str, Any] | None = None
    replica: dict[str, Any] | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))


@dataclass(frozen=True)
class OutputPolicySetProfile:
    name: str
    policy: str
    match: dict[str, Any] | None = None
    hintOnly: bool | None = None
    projectionMode: str | None = None
    selectors: dict[str, Any] | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))


@dataclass(frozen=True)
class OutputPolicySetSpec:
    defaults: OutputPolicySetDefaults
    policies: dict[str, OutputPolicySetInlinePolicy]
    profiles: list[OutputPolicySetProfile]
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class OutputPolicySet:
    metadata: OutputPolicySetMetadata
    spec: OutputPolicySetSpec
    apiVersion: str = "vuoro.outctl/v1alpha1"
    kind: str = "OutputPolicySet"
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OutputPolicySet:
        return _from_dict(cls, data)


# ---------------------------------------------------------------------------
# CommandResultEnvelope models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandResultInvocation:
    argv_display: list[str]
    shell: bool
    cwd: str
    host_id: str
    harness: str
    started_at: str
    ended_at: str | None = None
    duration_ms: int | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CommandResultCommand:
    started: bool
    exit_code: int | None
    signal: int | str | None
    timed_out: bool
    cancelled: bool
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CommandResultCaptureSource:
    availability: str
    host_id: str
    path: str
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CommandResultCapture:
    status: str
    stdout_bytes: int
    stderr_bytes: int
    truncated: bool
    manifest_sha256: str
    source: CommandResultCaptureSource
    stdout_lines: int | None = None
    stderr_lines: int | None = None
    event_count: int | None = None
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CommandResultProjection:
    projection_id: str
    policy_ref: str
    policy_digest: str
    mode: str
    bytes: int
    lines: int
    estimated_tokens: int
    lossy: bool
    normalized: bool
    deduplicated: bool
    redacted: bool
    sha256: str
    inline_text: str | None = None
    projection_ref: str | None = None
    token_estimator: str | None = None
    omitted_stdout_lines: int | None = None
    omitted_stderr_lines: int | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CommandResultRetrieval:
    available: bool
    capabilities: list[str]
    examples: list[str] | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CommandResultEnvelope:
    capture_ref: str
    capture_id: str
    bindings: dict[str, str | None]
    invocation: CommandResultInvocation
    command: CommandResultCommand
    capture: CommandResultCapture
    projection: CommandResultProjection
    retrieval: CommandResultRetrieval
    replicas: list[dict[str, Any]]
    metrics: dict[str, int | float | str | None]
    schema_version: str = "vuoro.outctl.result/v1alpha1"
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CommandResultEnvelope:
        return _from_dict(cls, data)


# ---------------------------------------------------------------------------
# CaptureManifest models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureManifestSource:
    host_id: str
    workspace_id: str
    cwd: str
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifestPolicy:
    name: str
    digest: str
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifestCapture:
    status: str
    required: bool
    max_bytes: int
    truncated: bool
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifestStream:
    path: str
    bytes: int
    sha256: str | None
    complete: bool
    lines: int | None = None
    last_captured_offset: int | None = None
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifestStreams:
    stdout: CaptureManifestStream
    stderr: CaptureManifestStream
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifestEventIndex:
    path: str
    bytes: int
    sha256: str
    events: list[dict[str, Any]]
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifestProjection:
    projection_id: str
    policy_ref: str
    policy_digest: str
    mode: str
    bytes: int
    lines: int
    estimated_tokens: int
    lossy: bool
    normalized: bool
    deduplicated: bool
    redacted: bool
    sha256: str
    extra: dict[str, Any] | None = None


@dataclass(frozen=True)
class CaptureManifest:
    capture_id: str
    created_at: str
    source: CaptureManifestSource
    bindings: dict[str, Any]
    policy: CaptureManifestPolicy
    command: CommandResultCommand
    capture: CaptureManifestCapture
    streams: CaptureManifestStreams
    event_index: CaptureManifestEventIndex
    schema_version: str = "vuoro.outctl.capture/v1alpha1"
    finalized_at: str | None = None
    projections: list[CaptureManifestProjection] | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CaptureManifest:
        return _from_dict(cls, data)


# ---------------------------------------------------------------------------
# AuditEvent model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    occurred_at: str
    capture_ref: str
    capture_manifest_sha256: str
    bindings: dict[str, Any]
    actor: dict[str, Any]
    schema_version: str = "vuoro.outctl.audit-event/v1alpha1"
    projection_sha256: str | None = None
    policy_digest: str | None = None
    status: dict[str, Any] | None = None
    metrics: dict[str, Any] | None = None
    replica: dict[str, Any] | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _to_dict(self))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditEvent:
        return _from_dict(cls, data)
