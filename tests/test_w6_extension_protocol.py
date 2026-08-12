from __future__ import annotations

import json

import pytest

from outctl.extensions.contracts import (
    MAX_REQUEST_BYTES,
    ExtensionContext,
    ExtensionKind,
    ExtensionPhase,
    ExtensionRequest,
    ExtensionResult,
)
from outctl.extensions.discovery import ExtensionPin
from outctl.extensions.protocol import (
    ExtensionInvocation,
    ExtensionProtocolError,
    parse_result,
    result_document,
    strict_json_document,
)

DIGEST = "sha256:" + "a" * 64
PIN = ExtensionPin("test-extension", "test-package", "1.0.0", "test_plugin:extension", DIGEST)


def _commissioning(input_value: dict[str, object] | None = None) -> ExtensionInvocation:
    return ExtensionInvocation(
        PIN,
        ExtensionRequest(
            PIN.extension_id,
            ExtensionContext(
                "workspace-1",
                "session-1",
                None,
                2_000,
                ExtensionPhase.COMMISSIONING,
                DIGEST,
            ),
            input_value or {},
            4_096,
        ),
    )


def _projection() -> ExtensionInvocation:
    return ExtensionInvocation(
        PIN,
        ExtensionRequest(
            PIN.extension_id,
            ExtensionContext(
                "workspace-1",
                "session-1",
                "snapshot-1",
                2_000,
                ExtensionPhase.PROJECTION,
                None,
                "policy://test",
                DIGEST,
            ),
            {"projection": {"lines": ["bounded"]}},
            4_096,
        ),
    )


def test_commissioning_and_projection_protocol_round_trip_exact_bindings() -> None:
    for invocation in (_commissioning({"facts": ["a"]}), _projection()):
        decoded = ExtensionInvocation.from_bytes(invocation.to_bytes())
        assert decoded == invocation
        commissioning = decoded.request.context.phase is ExtensionPhase.COMMISSIONING
        result = ExtensionResult.accepted(
            decoded.request,
            ExtensionKind.FACTS if commissioning else ExtensionKind.PROJECTION_CANDIDATE,
            {"facts": {"bounded": True}}
            if commissioning
            else {"title": "Bounded", "lines": ["one"], "lossy": False},
        )
        assert parse_result(result_document(decoded, result), decoded).to_dict() == result.to_dict()


def test_protocol_rejects_duplicates_trailing_documents_and_nonfinite_values() -> None:
    with pytest.raises(ExtensionProtocolError, match="duplicate"):
        strict_json_document(b'{"a":1,"a":2}', maximum=100)
    with pytest.raises(ExtensionProtocolError, match="malformed"):
        strict_json_document(b'{"a":1} {}', maximum=100)
    with pytest.raises(ExtensionProtocolError, match="non-finite"):
        strict_json_document(b'{"a":NaN}', maximum=100)


def test_request_exact_byte_limit_is_accepted_and_limit_plus_one_is_rejected() -> None:
    base = _commissioning({"a": "", "b": ""})
    required = MAX_REQUEST_BYTES - len(base.to_bytes())
    left = min(required, 32 * 1024)
    right = required - left
    exact = _commissioning({"a": "x" * left, "b": "y" * right})
    assert len(exact.to_bytes()) == MAX_REQUEST_BYTES
    over = _commissioning({"a": "x" * left, "b": "y" * (right + 1)})
    with pytest.raises(ExtensionProtocolError, match="request budget"):
        over.to_bytes()


def test_only_facts_and_projection_candidates_cross_w6_boundary() -> None:
    invocation = _commissioning()
    for kind in (ExtensionKind.POLICY_CANDIDATE, ExtensionKind.SANITIZER):
        result = ExtensionResult.accepted(invocation.request, kind, {"candidate": True})
        with pytest.raises(ExtensionProtocolError, match="invalid for its phase"):
            result_document(invocation, result)
    wrong_phase = ExtensionResult.accepted(
        invocation.request, ExtensionKind.PROJECTION_CANDIDATE, {"candidate": True}
    )
    with pytest.raises(ExtensionProtocolError, match="invalid for its phase"):
        result_document(invocation, wrong_phase)
    projection = _projection()
    projection_facts = ExtensionResult.accepted(
        projection.request, ExtensionKind.FACTS, {"ready": True}
    )
    with pytest.raises(ExtensionProtocolError, match="invalid for its phase"):
        result_document(projection, projection_facts)
    with pytest.raises(ValueError, match="outside the extension boundary"):
        ExtensionResult.accepted(
            invocation.request,
            ExtensionKind.FACTS,
            {"can_authorize_execution": True},
        )
    for forbidden in (
        "commissioned",
        "trust-domain",
        "execution_authorized",
        "capture_required",
        "persistence",
        "disclosure",
        "redaction",
        "budget",
        "limits",
    ):
        with pytest.raises(ValueError, match="outside the extension boundary"):
            ExtensionResult.accepted(
                invocation.request,
                ExtensionKind.FACTS,
                {forbidden: True},
            )


@pytest.mark.parametrize(
    "forbidden",
    (
        "can-authorize-execution",
        "can_authorize_execution",
        "canauthorizeexecution",
        "canAuthorizeExecution",
        "CanAuthorizeExecution",
        "trustDomain",
        "captureRequired",
        "rawOutput",
        "secretValue",
        "commandScope",
        "stdinRef",
        "PersistenceMode",
        "disclosure.mode",
        "redaction required",
        "LifecycleState",
        "MAX_RESULT_BYTES",
    ),
)
def test_forbidden_semantic_key_variants_are_rejected_recursively(forbidden: str) -> None:
    invocation = _commissioning()
    with pytest.raises(ValueError, match="outside the extension boundary"):
        ExtensionResult.accepted(
            invocation.request,
            ExtensionKind.FACTS,
            {"facts": {"nested": {forbidden: True}}},
        )


def test_kind_payload_shapes_are_exact_and_bounded() -> None:
    commissioning = _commissioning()
    for payload in (
        {"ready": True},
        {"facts": []},
        {"facts": {}, "extra": True},
    ):
        result = ExtensionResult.accepted(commissioning.request, ExtensionKind.FACTS, payload)
        with pytest.raises(ExtensionProtocolError, match="facts contribution"):
            result_document(commissioning, result)
    projection = _projection()
    for payload in (
        {"title": "x", "lines": []},
        {"title": "", "lines": [], "lossy": False},
        {"title": "x", "lines": ["x" * 513], "lossy": False},
        {"title": "x", "lines": [], "lossy": 0},
    ):
        result = ExtensionResult.accepted(
            projection.request, ExtensionKind.PROJECTION_CANDIDATE, payload
        )
        with pytest.raises(ExtensionProtocolError):
            result_document(projection, result)


def test_invocation_digest_rejects_any_mutation() -> None:
    value = json.loads(_commissioning({"ready": True}).to_bytes())
    value["input"]["ready"] = False
    with pytest.raises(ExtensionProtocolError, match="digest does not match"):
        ExtensionInvocation.from_bytes(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )


def test_mutated_result_objects_are_revalidated_at_the_protocol_boundary() -> None:
    invocation = _commissioning()
    result = ExtensionResult.accepted(
        invocation.request,
        ExtensionKind.FACTS,
        {"facts": {"observed": True}},
    )
    facts = result.payload["facts"]
    assert isinstance(facts, dict)
    facts["execution-authorized"] = True
    with pytest.raises(ExtensionProtocolError, match="payload is invalid"):
        result_document(invocation, result)


def test_projection_and_raw_protocol_reject_nested_forbidden_variants() -> None:
    projection = _projection()
    result = ExtensionResult.accepted(
        projection.request,
        ExtensionKind.PROJECTION_CANDIDATE,
        {"title": "Bounded", "lines": ["one"], "lossy": False},
    )
    lines = result.payload["lines"]
    assert isinstance(lines, list)
    lines.append({"trustDomain": "trusted-local"})  # type: ignore[arg-type]
    with pytest.raises(ExtensionProtocolError, match="payload is invalid"):
        result_document(projection, result)

    invocation = _commissioning()
    valid = ExtensionResult.accepted(
        invocation.request,
        ExtensionKind.FACTS,
        {"facts": {"observed": True}},
    )
    document = json.loads(result_document(invocation, valid))
    document["payload"]["facts"]["nested"] = {"captureRequired": True}
    with pytest.raises(ExtensionProtocolError, match="payload is invalid"):
        parse_result(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
            invocation,
        )
