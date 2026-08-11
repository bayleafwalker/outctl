"""Contract-only native-engine boundary for W2.

No subprocess, Rust extension, or Python reference-engine import is performed
here.  W3 may provide an implementation behind these protocols.
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
    "NativeEngine",
    "NegotiatedCapabilities",
    "PolicySnapshot",
    "negotiate_capabilities",
]
