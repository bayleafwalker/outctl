"""Canonical, bounded JSON protocol for the isolated extension worker."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Final, cast

from outctl.extensions.contracts import (
    MAX_REQUEST_BYTES,
    ExtensionContext,
    ExtensionKind,
    ExtensionPhase,
    ExtensionRequest,
    ExtensionResult,
    ExtensionStatus,
    JsonValue,
    _validate_json,
)
from outctl.extensions.discovery import ExtensionPin

INVOCATION_SCHEMA: Final = "vuoro.outctl.extension-invocation/v1"
RESULT_SCHEMA: Final = "vuoro.outctl.extension-result/v1"
MAX_PROTOCOL_DEPTH: Final = 32
MAX_PROTOCOL_ITEMS: Final = 2_048
MIN_PROTOCOL_RESULT_BYTES: Final = 2_048
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")


class ExtensionProtocolError(ValueError):
    """Raised for malformed, ambiguous, or over-budget protocol material."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, child in pairs:
        if key in value:
            raise ExtensionProtocolError("extension JSON contains a duplicate key")
        value[key] = child
    return value


def _walk(value: object, *, depth: int = 0, budget: list[int] | None = None) -> None:
    if depth > MAX_PROTOCOL_DEPTH:
        raise ExtensionProtocolError("extension JSON exceeds the nesting limit")
    remaining = budget if budget is not None else [MAX_PROTOCOL_ITEMS]
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ExtensionProtocolError("extension JSON exceeds the item limit")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ExtensionProtocolError("extension JSON contains a non-finite number")
        return
    if isinstance(value, list):
        for child in value:
            _walk(child, depth=depth + 1, budget=remaining)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for child in value.values():
            _walk(child, depth=depth + 1, budget=remaining)
        return
    raise ExtensionProtocolError("extension protocol is not canonical JSON data")


def canonical_json_bytes(value: object) -> bytes:
    _walk(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExtensionProtocolError("extension protocol cannot be encoded") from exc


def strict_json_document(body: bytes, *, maximum: int) -> dict[str, object]:
    if not body or len(body) > maximum:
        raise ExtensionProtocolError("extension JSON document is empty or over budget")
    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ExtensionProtocolError("extension JSON contains a non-finite number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExtensionProtocolError("extension JSON document is malformed") from exc
    _walk(value)
    if not isinstance(value, dict):
        raise ExtensionProtocolError("extension JSON document must be an object")
    return cast(dict[str, object], value)


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ExtensionProtocolError(f"{label} has an invalid shape")


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExtensionProtocolError(f"{label} must be a non-empty string")
    return value


def _validate_w6_payload(kind: ExtensionKind, payload: object) -> dict[str, JsonValue]:
    try:
        checked = _validate_json(payload)
    except (TypeError, ValueError) as exc:
        raise ExtensionProtocolError("extension contribution payload is invalid") from exc
    if not isinstance(checked, dict):
        raise ExtensionProtocolError("extension contribution payload must be an object")
    if kind is ExtensionKind.FACTS:
        if set(checked) != {"facts"} or not isinstance(checked["facts"], dict):
            raise ExtensionProtocolError("facts contribution has an invalid shape")
        canonical_json_bytes(checked)
        return checked
    if kind is ExtensionKind.PROJECTION_CANDIDATE:
        if set(checked) != {"title", "lines", "lossy"}:
            raise ExtensionProtocolError("projection contribution has an invalid shape")
        title = checked["title"]
        lines = checked["lines"]
        lossy = checked["lossy"]
        if not isinstance(title, str) or not 1 <= len(title) <= 160:
            raise ExtensionProtocolError("projection title is outside its bounds")
        if (
            not isinstance(lines, list)
            or len(lines) > 128
            or not all(isinstance(line, str) and len(line) <= 512 for line in lines)
        ):
            raise ExtensionProtocolError("projection lines are outside their bounds")
        if type(lossy) is not bool:
            raise ExtensionProtocolError("projection lossy flag must be boolean")
        canonical_json_bytes(checked)
        return checked
    raise ExtensionProtocolError("extension contribution kind is outside W6 scope")


@dataclass(frozen=True)
class ExtensionInvocation:
    pin: ExtensionPin
    request: ExtensionRequest

    def __post_init__(self) -> None:
        if self.pin.extension_id != self.request.extension_id:
            raise ExtensionProtocolError("extension request does not match its pin")
        if self.request.context.phase is ExtensionPhase.PROJECTION and (
            self.request.context.policy_ref is None or self.request.context.policy_digest is None
        ):
            raise ExtensionProtocolError("projection invocation requires the exact policy triple")
        if self.request.max_result_bytes < MIN_PROTOCOL_RESULT_BYTES:
            raise ExtensionProtocolError("extension result budget is too small for the protocol")

    def material(self) -> dict[str, object]:
        context = self.request.context
        context_value: dict[str, object] = {
            "workspace_id": context.workspace_id,
            "session_id": context.session_id,
        }
        if context.phase is ExtensionPhase.COMMISSIONING:
            context_value["commissioning_context_digest"] = context.commissioning_context_digest
        else:
            context_value["policy"] = {
                "snapshot_id": context.policy_snapshot_id,
                "ref": context.policy_ref,
                "digest": context.policy_digest,
            }
        return {
            "schema_version": INVOCATION_SCHEMA,
            "phase": context.phase.value,
            "extension": self.pin.to_dict(),
            "context": context_value,
            "input": dict(self.request.input),
            "limits": {
                "deadline_ms": context.deadline_ms,
                "max_result_bytes": self.request.max_result_bytes,
            },
        }

    @property
    def invocation_id(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_json_bytes(self.material())).hexdigest()

    def to_bytes(self) -> bytes:
        body = canonical_json_bytes({**self.material(), "invocation_id": self.invocation_id})
        if len(body) > MAX_REQUEST_BYTES:
            raise ExtensionProtocolError("extension invocation exceeds the request budget")
        return body

    @classmethod
    def from_bytes(cls, body: bytes) -> ExtensionInvocation:
        value = strict_json_document(body, maximum=MAX_REQUEST_BYTES)
        _exact_keys(
            value,
            {
                "schema_version",
                "invocation_id",
                "phase",
                "extension",
                "context",
                "input",
                "limits",
            },
            "extension invocation",
        )
        if value["schema_version"] != INVOCATION_SCHEMA:
            raise ExtensionProtocolError("extension invocation schema is unsupported")
        pin = ExtensionPin.from_dict(value["extension"])
        try:
            phase = ExtensionPhase(_string(value["phase"], "phase"))
        except ValueError as exc:
            raise ExtensionProtocolError("extension phase is unsupported") from exc
        context_value = value["context"]
        limits_value = value["limits"]
        input_value = value["input"]
        if not isinstance(context_value, dict) or not isinstance(limits_value, dict):
            raise ExtensionProtocolError("extension context or limits is malformed")
        if not isinstance(input_value, dict):
            raise ExtensionProtocolError("extension input must be an object")
        workspace_id = _string(context_value.get("workspace_id"), "workspace_id")
        session_id = _string(context_value.get("session_id"), "session_id")
        deadline_ms = limits_value.get("deadline_ms")
        max_result_bytes = limits_value.get("max_result_bytes")
        if isinstance(deadline_ms, bool) or not isinstance(deadline_ms, int):
            raise ExtensionProtocolError("deadline_ms must be an integer")
        if isinstance(max_result_bytes, bool) or not isinstance(max_result_bytes, int):
            raise ExtensionProtocolError("max_result_bytes must be an integer")
        if phase is ExtensionPhase.COMMISSIONING:
            _exact_keys(
                context_value,
                {"workspace_id", "session_id", "commissioning_context_digest"},
                "commissioning context",
            )
            context = ExtensionContext(
                workspace_id,
                session_id,
                None,
                deadline_ms,
                phase,
                _string(
                    context_value["commissioning_context_digest"],
                    "commissioning_context_digest",
                ),
            )
        else:
            _exact_keys(
                context_value,
                {"workspace_id", "session_id", "policy"},
                "projection context",
            )
            policy = context_value["policy"]
            if not isinstance(policy, dict):
                raise ExtensionProtocolError("projection policy binding must be an object")
            _exact_keys(policy, {"snapshot_id", "ref", "digest"}, "projection policy")
            context = ExtensionContext(
                workspace_id,
                session_id,
                _string(policy["snapshot_id"], "snapshot_id"),
                deadline_ms,
                phase,
                None,
                _string(policy["ref"], "policy ref"),
                _string(policy["digest"], "policy digest"),
            )
        request = ExtensionRequest(pin.extension_id, context, input_value, max_result_bytes)
        invocation = cls(pin, request)
        claimed_id = _string(value["invocation_id"], "invocation_id")
        if _DIGEST_RE.fullmatch(claimed_id) is None or claimed_id != invocation.invocation_id:
            raise ExtensionProtocolError("extension invocation digest does not match")
        return invocation


def result_document(invocation: ExtensionInvocation, result: ExtensionResult) -> bytes:
    if result.extension_id != invocation.pin.extension_id:
        raise ExtensionProtocolError("extension result identity does not match")
    expected_kind = (
        ExtensionKind.FACTS
        if invocation.request.context.phase is ExtensionPhase.COMMISSIONING
        else ExtensionKind.PROJECTION_CANDIDATE
    )
    if result.status is ExtensionStatus.ACCEPTED and result.kind is not expected_kind:
        raise ExtensionProtocolError("extension contribution kind is invalid for its phase")
    checked_payload = dict(result.payload)
    if result.status is ExtensionStatus.ACCEPTED:
        checked_payload = _validate_w6_payload(expected_kind, result.payload)
    safe_diagnostics = ["extension-diagnostic" for _item in result.diagnostics[:8]]
    value = {
        "schema_version": RESULT_SCHEMA,
        "invocation_id": invocation.invocation_id,
        "extension": invocation.pin.to_dict(),
        "status": result.status.value,
        "kind": result.kind.value if result.kind is not None else None,
        "payload": checked_payload,
        "diagnostics": safe_diagnostics,
    }
    body = canonical_json_bytes(value)
    if len(body) > invocation.request.max_result_bytes:
        raise ExtensionProtocolError("extension result exceeds the negotiated budget")
    return body


def parse_result(body: bytes, invocation: ExtensionInvocation) -> ExtensionResult:
    value = strict_json_document(body, maximum=invocation.request.max_result_bytes)
    _exact_keys(
        value,
        {
            "schema_version",
            "invocation_id",
            "extension",
            "status",
            "kind",
            "payload",
            "diagnostics",
        },
        "extension result",
    )
    if value["schema_version"] != RESULT_SCHEMA:
        raise ExtensionProtocolError("extension result schema is unsupported")
    if value["invocation_id"] != invocation.invocation_id:
        raise ExtensionProtocolError("extension result invocation binding does not match")
    if ExtensionPin.from_dict(value["extension"]) != invocation.pin:
        raise ExtensionProtocolError("extension result pin does not match")
    try:
        status = ExtensionStatus(_string(value["status"], "result status"))
        kind = None if value["kind"] is None else ExtensionKind(_string(value["kind"], "kind"))
    except ValueError as exc:
        raise ExtensionProtocolError("extension result status or kind is unsupported") from exc
    payload = value["payload"]
    diagnostics = value["diagnostics"]
    if not isinstance(payload, dict) or not isinstance(diagnostics, list):
        raise ExtensionProtocolError("extension result payload or diagnostics is malformed")
    if not all(item == "extension-diagnostic" for item in diagnostics):
        raise ExtensionProtocolError("extension diagnostics are not normalized")
    expected_kind = (
        ExtensionKind.FACTS
        if invocation.request.context.phase is ExtensionPhase.COMMISSIONING
        else ExtensionKind.PROJECTION_CANDIDATE
    )
    if status is ExtensionStatus.ACCEPTED and kind is not expected_kind:
        raise ExtensionProtocolError("extension contribution kind is invalid for its phase")
    if status is ExtensionStatus.ACCEPTED:
        payload = _validate_w6_payload(expected_kind, payload)
    return ExtensionResult(
        invocation.pin.extension_id,
        status,
        kind,
        cast(dict[str, JsonValue], payload),
        tuple(cast(list[str], diagnostics)),
        invocation.request.max_result_bytes,
    )


__all__ = [
    "ExtensionInvocation",
    "ExtensionProtocolError",
    "INVOCATION_SCHEMA",
    "RESULT_SCHEMA",
    "canonical_json_bytes",
    "parse_result",
    "result_document",
    "strict_json_document",
]
