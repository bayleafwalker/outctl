"""Python control-plane contracts for the non-executing v2 boundary.

This namespace is deliberately independent of the v1 capture and projection
engine.  It can be imported by a native-engine selector or policy compiler
without starting the reference engine's import graph.
"""

from outctl.control.contracts import (
    CapabilityNegotiationError,
    CapabilityRequirement,
    CaptureCommitment,
    CaptureDurability,
    EngineCapabilities,
    EngineFeature,
    EngineIdentity,
    NegotiatedCapabilities,
    PolicyBinding,
    PolicyCacheEntry,
    PolicySnapshot,
    SinkPolicy,
    negotiate_capabilities,
)

__all__ = [
    "CapabilityNegotiationError",
    "CapabilityRequirement",
    "CaptureCommitment",
    "CaptureDurability",
    "EngineCapabilities",
    "EngineFeature",
    "EngineIdentity",
    "NegotiatedCapabilities",
    "PolicyBinding",
    "PolicyCacheEntry",
    "PolicySnapshot",
    "SinkPolicy",
    "negotiate_capabilities",
]
