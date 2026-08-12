from __future__ import annotations

from dataclasses import replace

import pytest

from outctl.extensions import (
    ExtensionContext,
    ExtensionContributionRecord,
    ExtensionInvocation,
    ExtensionKind,
    ExtensionPhase,
    ExtensionPin,
    ExtensionProtocolError,
    ExtensionRequest,
    ExtensionResult,
    canonical_contribution_material,
    contribution_record,
)

DIGEST = "sha256:" + "c" * 64


def _invocation(extension_id: str) -> ExtensionInvocation:
    pin = ExtensionPin(
        extension_id,
        f"package-{extension_id}",
        "1.0.0",
        f"plugin_{extension_id.replace('-', '_')}:extension",
        DIGEST,
    )
    return ExtensionInvocation(
        pin,
        ExtensionRequest(
            extension_id,
            ExtensionContext(
                "workspace-1",
                "session-1",
                None,
                1_000,
                ExtensionPhase.COMMISSIONING,
                DIGEST,
            ),
            {},
            4_096,
        ),
    )


def _record(extension_id: str, value: str) -> ExtensionContributionRecord:
    invocation = _invocation(extension_id)
    return contribution_record(
        invocation,
        ExtensionResult.accepted(
            invocation.request, ExtensionKind.FACTS, {"facts": {"value": value}}
        ),
    )


def test_contribution_material_is_sorted_bound_and_order_independent() -> None:
    first = _record("extension-a", "one")
    second = _record("extension-b", "two")
    assert canonical_contribution_material([second, first]) == canonical_contribution_material(
        [first, second]
    )
    changed = _record("extension-a", "changed")
    assert first.result_digest != changed.result_digest
    assert canonical_contribution_material([first]) != canonical_contribution_material([changed])


def test_duplicate_or_mismatched_contribution_identity_fails_closed() -> None:
    record = _record("extension-a", "one")
    with pytest.raises(ExtensionProtocolError, match="unique"):
        canonical_contribution_material([record, record])
    invocation = _invocation("extension-a")
    other = _invocation("extension-b")
    result = ExtensionResult.accepted(
        other.request, ExtensionKind.FACTS, {"facts": {"ready": True}}
    )
    with pytest.raises(ExtensionProtocolError, match="identity"):
        contribution_record(invocation, result)

    with pytest.raises(ExtensionProtocolError, match="commissioning records"):
        replace(record, kind=ExtensionKind.POLICY_CANDIDATE)
    bad_result = ExtensionResult.accepted(
        invocation.request, ExtensionKind.POLICY_CANDIDATE, {"ready": True}
    )
    with pytest.raises(ExtensionProtocolError, match="outside W6 scope"):
        contribution_record(invocation, bad_result)


def test_projection_result_cannot_be_misrepresented_as_compile_time_contribution() -> None:
    invocation = _invocation("extension-a")
    projection_context = ExtensionContext(
        "workspace-1",
        "session-1",
        "snapshot-1",
        1_000,
        ExtensionPhase.PROJECTION,
        None,
        "policy://test",
        DIGEST,
    )
    projection = ExtensionInvocation(
        invocation.pin,
        ExtensionRequest(invocation.pin.extension_id, projection_context, {}, 4_096),
    )
    result = ExtensionResult.accepted(
        projection.request, ExtensionKind.PROJECTION_CANDIDATE, {"title": "bounded"}
    )
    with pytest.raises(ExtensionProtocolError, match="only commissioning"):
        contribution_record(projection, result)


def test_mutated_record_payload_is_revalidated_when_canonicalized() -> None:
    invocation = _invocation("extension-a")
    result = ExtensionResult.accepted(
        invocation.request,
        ExtensionKind.FACTS,
        {"facts": {"value": "one"}},
    )
    record = contribution_record(invocation, result)
    facts = result.payload["facts"]
    assert isinstance(facts, dict)
    facts["value"] = "changed-after-record"

    # The record retained an immutable exact snapshot, not the mutable result.
    material = canonical_contribution_material([record])
    assert material[0]["payload"] == {"facts": {"value": "one"}}
    with pytest.raises(ExtensionProtocolError, match="result digest"):
        replace(record, payload={"facts": {"value": "valid-but-stale"}})
