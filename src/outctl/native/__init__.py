"""Native-engine contracts and explicit W3 engine selection.

Importing this package remains side-effect free and does not load either
execution engine. The differential runner is deliberately a separate opt-in
module because it imports and executes the Python reference engine.
"""

from __future__ import annotations

from typing import Protocol

from outctl.control.contracts import (
    CapabilityRequirement,
    EngineCapabilities,
    NegotiatedCapabilities,
    PolicySnapshot,
    negotiate_capabilities,
)
from outctl.native.rollout import (
    HostArtifactPin,
    HostClass,
    RolloutEvidence,
    RolloutEvidenceError,
    RolloutMode,
    RolloutSelection,
    RolloutTrack,
    WaveGate,
    cohort_bucket,
    probe_native_capabilities,
    run_pinned_native,
    select_rollout_engines,
)
from outctl.native.selector import (
    EngineChoice,
    EngineSelection,
    NativeEngineUnavailable,
    select_engine,
)


class NativeEngine(Protocol):
    """The future execution-plane shape; W2 intentionally has no implementation."""

    def capabilities(self) -> EngineCapabilities:
        """Return immutable capabilities without starting a command."""

    def negotiate(self, required: CapabilityRequirement) -> NegotiatedCapabilities:
        """Negotiate features before a request is submitted."""

    def validate_policy(self, snapshot: PolicySnapshot) -> None:
        """Validate a pinned snapshot without compiling or widening it."""


__all__ = [
    "CapabilityRequirement",
    "EngineCapabilities",
    "EngineChoice",
    "EngineSelection",
    "NativeEngine",
    "NativeEngineUnavailable",
    "NegotiatedCapabilities",
    "PolicySnapshot",
    "negotiate_capabilities",
    "select_engine",
    "HostClass",
    "HostArtifactPin",
    "RolloutEvidence",
    "RolloutEvidenceError",
    "RolloutMode",
    "RolloutSelection",
    "RolloutTrack",
    "WaveGate",
    "cohort_bucket",
    "probe_native_capabilities",
    "run_pinned_native",
    "select_rollout_engines",
]
