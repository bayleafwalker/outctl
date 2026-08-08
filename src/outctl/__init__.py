"""Bounded, recoverable command-output capture and projection."""

from __future__ import annotations

from outctl.comparison import (
    ComparisonResult,
    compare_direct_wrapped,
    make_direct_reference,
)
from outctl.fixtures import FixtureGenerator, GeneratedFixture
from outctl.models import (
    AuditEvent,
    CaptureManifest,
    CaptureManifestCapture,
    CaptureManifestEventIndex,
    CaptureManifestPolicy,
    CaptureManifestProjection,
    CaptureManifestSource,
    CaptureManifestStream,
    CaptureManifestStreams,
    CommandResultCapture,
    CommandResultCaptureSource,
    CommandResultCommand,
    CommandResultEnvelope,
    CommandResultInvocation,
    CommandResultProjection,
    CommandResultRetrieval,
    OutputPolicy,
    OutputPolicyBudget,
    OutputPolicyCapture,
    OutputPolicyProjection,
    OutputPolicyRedaction,
    OutputPolicySet,
    OutputPolicySetDefaults,
    OutputPolicySetInlinePolicy,
    OutputPolicySetMetadata,
    OutputPolicySetProfile,
    OutputPolicySetSpec,
    OutputPolicySpec,
)
from outctl.policy import (
    PolicyCycleError,
    PolicyError,
    PolicyNotFoundError,
    PolicyValidationError,
    load_policy_set,
    policy_digest,
    resolve_and_digest,
    resolve_policy,
)
from outctl.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
    sha256_hex,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "__version__",
    # Models
    "AuditEvent",
    "CaptureManifest",
    "CaptureManifestCapture",
    "CaptureManifestEventIndex",
    "CaptureManifestPolicy",
    "CaptureManifestProjection",
    "CaptureManifestSource",
    "CaptureManifestStream",
    "CaptureManifestStreams",
    "CommandResultCapture",
    "CommandResultCaptureSource",
    "CommandResultCommand",
    "CommandResultEnvelope",
    "CommandResultInvocation",
    "CommandResultProjection",
    "CommandResultRetrieval",
    "OutputPolicy",
    "OutputPolicyBudget",
    "OutputPolicyCapture",
    "OutputPolicyProjection",
    "OutputPolicyRedaction",
    "OutputPolicySet",
    "OutputPolicySetDefaults",
    "OutputPolicySetInlinePolicy",
    "OutputPolicySetMetadata",
    "OutputPolicySetProfile",
    "OutputPolicySetSpec",
    "OutputPolicySpec",
    # Policy resolution
    "PolicyCycleError",
    "PolicyError",
    "PolicyNotFoundError",
    "PolicyValidationError",
    "load_policy_set",
    "policy_digest",
    "resolve_and_digest",
    "resolve_policy",
    # Serialization
    "canonical_json_bytes",
    "canonical_json_text",
    "canonical_sha256",
    "sha256_hex",
    # Fixtures
    "FixtureGenerator",
    "GeneratedFixture",
    # Comparison
    "ComparisonResult",
    "compare_direct_wrapped",
    "make_direct_reference",
]
