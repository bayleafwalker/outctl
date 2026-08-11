from __future__ import annotations

import importlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from outctl.control import (
    CapabilityNegotiationError,
    CapabilityRequirement,
    CaptureCommitment,
    CaptureDurability,
    EngineCapabilities,
    EngineFeature,
    EngineIdentity,
    PolicyBinding,
    PolicyCacheEntry,
    PolicySnapshot,
    SinkPolicy,
    negotiate_capabilities,
)
from outctl.extensions import (
    ExtensionContext,
    ExtensionKind,
    ExtensionRequest,
    ExtensionResult,
    ExtensionResultTooLarge,
    ExtensionStatus,
)

DIGEST = "sha256:" + "a" * 64
ROOT = Path(__file__).parents[1]


def _capabilities(**features: bool) -> EngineCapabilities:
    return EngineCapabilities(
        engine=EngineIdentity("native-test", "0.0.0", "test"),
        run_request_versions=("v2",),
        policy_snapshot_versions=("v2",),
        run_result_versions=("v2",),
        capture_manifest_versions=("v1alpha1", "v2"),
        direct_argv=features.get("direct_argv", True),
        explicit_shell=features.get("explicit_shell", False),
        stdin=features.get("stdin", False),
        retrieval=features.get("retrieval", True),
        one_version_back_read=True,
        max_argv_items=256,
        max_capture_bytes=1024,
        max_projection_bytes=1024,
    )


def _snapshot() -> PolicySnapshot:
    binding = PolicyBinding("snapshot-1", "policy://test", DIGEST)
    return PolicySnapshot(
        binding=binding,
        source_ref="git:policy.yaml",
        source_digest=DIGEST,
        cache=PolicyCacheEntry(
            "policy-cache://snapshot/snapshot-1", binding, "python-policy-control", 1000
        ),
        session_id="session-1",
        trust_domain="trusted-local",
        commissioned=True,
        sinks=(SinkPolicy("model", "restricted", "sanitized", True),),
        capture_commitment=CaptureCommitment.HOST_PERSISTENT,
        capture_durability=CaptureDurability.HOST,
        capture_required=True,
        issued_at="2026-08-11T17:00:00Z",
        expires_at="2026-08-11T18:00:00Z",
    )


def test_native_surface_does_not_import_v1_execution_modules() -> None:
    for name in tuple(sys.modules):
        if (
            name == "outctl"
            or name.startswith("outctl.native")
            or name.startswith("outctl.control")
        ):
            continue
        if name.startswith("outctl."):
            del sys.modules[name]
    importlib.invalidate_caches()
    importlib.import_module("outctl.native")
    assert "outctl.capture.runner" not in sys.modules
    assert "outctl.adapter" not in sys.modules
    assert "outctl.projection" not in sys.modules


def test_v1_root_name_still_lazy_loads_on_first_use() -> None:
    import outctl

    # Other test modules may have exercised the compatibility export during
    # collection.  Remove that cached attribute so this assertion probes the
    # lazy boundary itself rather than test ordering.
    outctl.__dict__.pop("OutputPolicy", None)
    assert "outctl.models" not in sys.modules
    assert outctl.OutputPolicy.__name__ == "OutputPolicy"
    assert "outctl.models" in sys.modules


def test_capability_negotiation_fails_closed_for_unsupported_shell() -> None:
    with pytest.raises(CapabilityNegotiationError, match="explicit_shell"):
        negotiate_capabilities(_capabilities(), [EngineFeature.EXPLICIT_SHELL])
    negotiated = negotiate_capabilities(
        _capabilities(explicit_shell=True),
        CapabilityRequirement(frozenset({EngineFeature.DIRECT_ARGV, EngineFeature.RETRIEVAL})),
    )
    assert negotiated.engine.engine.id == "native-test"


def test_capability_parsing_rejects_malformed_json_types() -> None:
    value = _capabilities().to_dict()
    value["features"]["explicit_shell"] = "false"  # type: ignore[index]
    with pytest.raises(ValueError, match="boolean"):
        EngineCapabilities.from_dict(value)


def test_policy_snapshot_requires_exact_cache_binding_and_expiry() -> None:
    snapshot = _snapshot()
    assert snapshot.is_valid_at(datetime(2026, 8, 11, 17, 30, tzinfo=UTC))
    assert not snapshot.is_valid_at(datetime(2026, 8, 11, 18, 0, tzinfo=UTC))
    bad_binding = PolicyBinding("snapshot-other", "policy://test", DIGEST)
    with pytest.raises(ValueError, match="does not bind"):
        PolicySnapshot(
            **{
                **snapshot.__dict__,
                "cache": PolicyCacheEntry(
                    "policy-cache://snapshot/snapshot-other",
                    bad_binding,
                    "python-policy-control",
                    1000,
                ),
            }
        )


def test_policy_snapshot_serializes_to_the_frozen_schema() -> None:
    schema = json.loads(
        (ROOT / "schemas/v2/policy-snapshot.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(_snapshot().to_dict())


def test_extension_result_is_bounded_and_cannot_claim_authority() -> None:
    request = ExtensionRequest(
        "ext.test",
        ExtensionContext("workspace-1", "session-1", "snapshot-1", 100),
        max_result_bytes=128,
    )
    result = ExtensionResult.accepted(request, ExtensionKind.FACTS, {"ready": True})
    assert result.status is ExtensionStatus.ACCEPTED
    assert result.encoded_bytes <= 128
    with pytest.raises(ValueError, match="outside the extension boundary"):
        ExtensionResult.accepted(request, ExtensionKind.FACTS, {"can_retry": True})
    with pytest.raises(ExtensionResultTooLarge):
        ExtensionResult.accepted(request, ExtensionKind.FACTS, {"text": "x" * 100})

    with pytest.raises(ExtensionResultTooLarge):
        ExtensionResult.accepted(
            request,
            ExtensionKind.FACTS,
            {"ready": True},
            diagnostics=("d" * 512,) * 4,
        )


def test_failed_extension_result_has_no_contribution_payload() -> None:
    request = ExtensionRequest(
        "ext.test",
        ExtensionContext("workspace-1", "session-1", "snapshot-1", 100),
    )
    result = ExtensionResult.failed(request, ExtensionStatus.TIMED_OUT, diagnostics=("deadline",))
    assert result.to_dict()["payload"] == {}
