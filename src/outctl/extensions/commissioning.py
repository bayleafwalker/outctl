"""Canonical records for binding extension contributions into policy source material."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import cast

from outctl.extensions.contracts import (
    ExtensionKind,
    ExtensionPhase,
    ExtensionResult,
    ExtensionStatus,
    JsonValue,
)
from outctl.extensions.discovery import ExtensionPin
from outctl.extensions.protocol import (
    RESULT_SCHEMA,
    ExtensionInvocation,
    ExtensionProtocolError,
    canonical_json_bytes,
    result_document,
)


def _freeze_json(value: JsonValue) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(child) for child in value)
    return value


def _thaw_json(value: object) -> JsonValue:
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ExtensionProtocolError("commissioning record payload keys must be strings")
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw_json(child) for child in value]
    return cast(JsonValue, value)


@dataclass(frozen=True)
class ExtensionContributionRecord:
    """One deterministic, raw-free commissioning result bound by source_digest."""

    pin: ExtensionPin
    invocation_id: str
    phase: ExtensionPhase
    status: ExtensionStatus
    kind: ExtensionKind | None
    payload: Mapping[str, JsonValue]
    result_digest: str
    diagnostic_count: int = field(default=0, repr=False, compare=False)

    def _validated_payload(self) -> dict[str, JsonValue]:
        thawed = _thaw_json(self.payload)
        if not isinstance(thawed, dict):
            raise ExtensionProtocolError("commissioning record payload must be an object")
        validated = ExtensionResult(
            self.pin.extension_id,
            self.status,
            self.kind,
            thawed,
        ).payload
        if self.status is ExtensionStatus.ACCEPTED and (
            self.kind is not ExtensionKind.FACTS
            or set(validated) != {"facts"}
            or not isinstance(validated["facts"], dict)
        ):
            raise ExtensionProtocolError("commissioning records accept only exact facts payloads")
        return dict(validated)

    def _expected_result_digest(self, payload: Mapping[str, JsonValue]) -> str:
        material = {
            "schema_version": RESULT_SCHEMA,
            "invocation_id": self.invocation_id,
            "extension": self.pin.to_dict(),
            "status": self.status.value,
            "kind": self.kind.value if self.kind is not None else None,
            "payload": dict(payload),
            "diagnostics": ["extension-diagnostic"] * self.diagnostic_count,
        }
        return "sha256:" + hashlib.sha256(canonical_json_bytes(material)).hexdigest()

    def _verified_payload(self) -> dict[str, JsonValue]:
        payload = self._validated_payload()
        if self._expected_result_digest(payload) != self.result_digest:
            raise ExtensionProtocolError(
                "commissioning contribution payload does not match its result digest"
            )
        return payload

    def __post_init__(self) -> None:
        if self.phase is not ExtensionPhase.COMMISSIONING:
            raise ExtensionProtocolError("source contribution phase must be commissioning")
        if (
            re.fullmatch(r"sha256:[a-f0-9]{64}", self.invocation_id) is None
            or re.fullmatch(r"sha256:[a-f0-9]{64}", self.result_digest) is None
        ):
            raise ExtensionProtocolError("source contribution digests must be sha256:<hex>")
        if not 0 <= self.diagnostic_count <= 8:
            raise ExtensionProtocolError("source contribution diagnostic count is invalid")
        # Snapshot nested data into read-only containers, then verify that the
        # exact payload still hashes to the isolated result document.
        payload = self._validated_payload()
        object.__setattr__(self, "payload", cast(Mapping[str, JsonValue], _freeze_json(payload)))
        self._verified_payload()

    def to_dict(self) -> dict[str, object]:
        return {
            "extension": self.pin.to_dict(),
            "invocation_id": self.invocation_id,
            "phase": self.phase.value,
            "status": self.status.value,
            "kind": self.kind.value if self.kind is not None else None,
            "payload": self._verified_payload(),
            "result_digest": self.result_digest,
        }


def contribution_record(
    invocation: ExtensionInvocation, result: ExtensionResult
) -> ExtensionContributionRecord:
    if invocation.request.context.phase is not ExtensionPhase.COMMISSIONING:
        raise ExtensionProtocolError("only commissioning results can become source contributions")
    if result.extension_id != invocation.pin.extension_id:
        raise ExtensionProtocolError("contribution identity does not match its invocation")
    if result.status is ExtensionStatus.ACCEPTED and result.kind is not ExtensionKind.FACTS:
        raise ExtensionProtocolError("contribution kind is outside W6 scope")
    encoded = result_document(invocation, result)
    return ExtensionContributionRecord(
        pin=invocation.pin,
        invocation_id=invocation.invocation_id,
        phase=ExtensionPhase.COMMISSIONING,
        status=result.status,
        kind=result.kind,
        payload=result.payload,
        result_digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
        diagnostic_count=min(len(result.diagnostics), 8),
    )


def canonical_contribution_material(
    records: Iterable[ExtensionContributionRecord],
) -> list[dict[str, object]]:
    """Return stable source-digest material; duplicate identities fail closed."""
    ordered = sorted(records, key=lambda record: record.pin.extension_id)
    ids = [record.pin.extension_id for record in ordered]
    if len(ids) != len(set(ids)):
        raise ExtensionProtocolError("commissioning contribution ids must be unique")
    material = [record.to_dict() for record in ordered]
    # Validate the complete aggregate through the same canonical JSON limits.
    canonical_json_bytes(material)
    return material


__all__ = [
    "ExtensionContributionRecord",
    "canonical_contribution_material",
    "contribution_record",
]
