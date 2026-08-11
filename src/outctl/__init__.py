"""Bounded, recoverable command-output capture and projection.

The original Python v1 API is kept at the package root for compatibility, but
its implementation modules are resolved on first use.  This matters for the
v2 control/native boundary: capability and policy negotiation can be imported
without importing the subprocess runner, projection engine, or CLI.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "0.1.0.dev0"

# Keep this map explicit.  Apart from preserving the public v1 names, it makes
# it auditable that a new control/native import does not accidentally pull in
# the reference engine.
_LAZY_EXPORTS: dict[str, tuple[str, str | None]] = {
    # Models
    "AuditEvent": ("outctl.models", "AuditEvent"),
    "CaptureManifest": ("outctl.models", "CaptureManifest"),
    "CaptureManifestCapture": ("outctl.models", "CaptureManifestCapture"),
    "CaptureManifestEventIndex": ("outctl.models", "CaptureManifestEventIndex"),
    "CaptureManifestPolicy": ("outctl.models", "CaptureManifestPolicy"),
    "CaptureManifestProjection": ("outctl.models", "CaptureManifestProjection"),
    "CaptureManifestSource": ("outctl.models", "CaptureManifestSource"),
    "CaptureManifestStream": ("outctl.models", "CaptureManifestStream"),
    "CaptureManifestStreams": ("outctl.models", "CaptureManifestStreams"),
    "CommandResultCapture": ("outctl.models", "CommandResultCapture"),
    "CommandResultCaptureSource": ("outctl.models", "CommandResultCaptureSource"),
    "CommandResultCommand": ("outctl.models", "CommandResultCommand"),
    "CommandResultEnvelope": ("outctl.models", "CommandResultEnvelope"),
    "CommandResultInvocation": ("outctl.models", "CommandResultInvocation"),
    "CommandResultProjection": ("outctl.models", "CommandResultProjection"),
    "CommandResultRetrieval": ("outctl.models", "CommandResultRetrieval"),
    "OutputPolicy": ("outctl.models", "OutputPolicy"),
    "OutputPolicyBudget": ("outctl.models", "OutputPolicyBudget"),
    "OutputPolicyCapture": ("outctl.models", "OutputPolicyCapture"),
    "OutputPolicyProjection": ("outctl.models", "OutputPolicyProjection"),
    "OutputPolicyRedaction": ("outctl.models", "OutputPolicyRedaction"),
    "OutputPolicySet": ("outctl.models", "OutputPolicySet"),
    "OutputPolicySetDefaults": ("outctl.models", "OutputPolicySetDefaults"),
    "OutputPolicySetInlinePolicy": ("outctl.models", "OutputPolicySetInlinePolicy"),
    "OutputPolicySetMetadata": ("outctl.models", "OutputPolicySetMetadata"),
    "OutputPolicySetProfile": ("outctl.models", "OutputPolicySetProfile"),
    "OutputPolicySetSpec": ("outctl.models", "OutputPolicySetSpec"),
    "OutputPolicySpec": ("outctl.models", "OutputPolicySpec"),
    # Policy resolution
    "PolicyCycleError": ("outctl.policy", "PolicyCycleError"),
    "PolicyError": ("outctl.policy", "PolicyError"),
    "PolicyNotFoundError": ("outctl.policy", "PolicyNotFoundError"),
    "PolicyValidationError": ("outctl.policy", "PolicyValidationError"),
    "load_policy_set": ("outctl.policy", "load_policy_set"),
    "policy_digest": ("outctl.policy", "policy_digest"),
    "resolve_and_digest": ("outctl.policy", "resolve_and_digest"),
    "resolve_policy": ("outctl.policy", "resolve_policy"),
    # Serialization
    "canonical_json_bytes": ("outctl.serialization", "canonical_json_bytes"),
    "canonical_json_text": ("outctl.serialization", "canonical_json_text"),
    "canonical_sha256": ("outctl.serialization", "canonical_sha256"),
    "sha256_hex": ("outctl.serialization", "sha256_hex"),
    # Fixtures and comparison
    "FixtureGenerator": ("outctl.fixtures", "FixtureGenerator"),
    "GeneratedFixture": ("outctl.fixtures", "GeneratedFixture"),
    "ComparisonResult": ("outctl.comparison", "ComparisonResult"),
    "compare_direct_wrapped": ("outctl.comparison", "compare_direct_wrapped"),
    "make_direct_reference": ("outctl.comparison", "make_direct_reference"),
    "build_result_envelope": ("outctl.envelope", "build_result_envelope"),
}


def __getattr__(name: str) -> Any:
    """Resolve a legacy v1 export only when the caller actually uses it."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    module = import_module(module_name)
    value = module if attribute is None else getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY_EXPORTS})


__all__ = ["__version__", *_LAZY_EXPORTS]
