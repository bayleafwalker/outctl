"""Canonical records for binding extension contributions into policy source material."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from outctl.extensions.contracts import (
    ExtensionKind,
    ExtensionPhase,
    ExtensionResult,
    ExtensionStatus,
    JsonValue,
)
from outctl.extensions.discovery import ExtensionPin
from outctl.extensions.protocol import (
    ExtensionInvocation,
    ExtensionProtocolError,
    canonical_json_bytes,
    result_document,
)


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

    def _validated_payload(self) -> Mapping[str, JsonValue]:
        validated = ExtensionResult(
            self.pin.extension_id,
            self.status,
            self.kind,
            self.payload,
        ).payload
        if self.status is ExtensionStatus.ACCEPTED and (
            self.kind is not ExtensionKind.FACTS
            or set(validated) != {"facts"}
            or not isinstance(validated["facts"], dict)
        ):
            raise ExtensionProtocolError("commissioning records accept only exact facts payloads")
        return validated

    def __post_init__(self) -> None:
        if self.phase is not ExtensionPhase.COMMISSIONING:
            raise ExtensionProtocolError("source contribution phase must be commissioning")
        if (
            re.fullmatch(r"sha256:[a-f0-9]{64}", self.invocation_id) is None
            or re.fullmatch(r"sha256:[a-f0-9]{64}", self.result_digest) is None
        ):
            raise ExtensionProtocolError("source contribution digests must be sha256:<hex>")
        # Reuse the result validator so direct construction cannot bypass
        # authority-field or non-accepted-payload restrictions. Revalidate in
        # to_dict as well because frozen dataclasses do not deep-freeze mappings.
        object.__setattr__(self, "payload", self._validated_payload())

    def to_dict(self) -> dict[str, object]:
        return {
            "extension": self.pin.to_dict(),
            "invocation_id": self.invocation_id,
            "phase": self.phase.value,
            "status": self.status.value,
            "kind": self.kind.value if self.kind is not None else None,
            "payload": dict(self._validated_payload()),
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
