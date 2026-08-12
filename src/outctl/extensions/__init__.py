"""Bounded Python extension contracts.

Extensions are adaptive inputs to commissioning or an explicitly bounded slow
path.  They never authorize execution, retry, persistence, lifecycle, or
publication. Discovery is metadata-only; extension code is loaded exclusively
inside the fail-closed isolated worker.
"""

from outctl.extensions.commissioning import (
    ExtensionContributionRecord,
    canonical_contribution_material,
    contribution_record,
)
from outctl.extensions.contracts import (
    ExtensionContext,
    ExtensionKind,
    ExtensionPhase,
    ExtensionProtocol,
    ExtensionRequest,
    ExtensionResult,
    ExtensionResultTooLarge,
    ExtensionStatus,
)
from outctl.extensions.discovery import (
    DiscoveredExtension,
    ExtensionDiscoveryError,
    ExtensionPin,
    discover_extensions,
    select_extension,
)
from outctl.extensions.protocol import ExtensionInvocation, ExtensionProtocolError
from outctl.extensions.slow_path import ExtensionSandboxUnavailable, invoke_extension

__all__ = [
    "DiscoveredExtension",
    "ExtensionContext",
    "ExtensionContributionRecord",
    "ExtensionDiscoveryError",
    "ExtensionKind",
    "ExtensionInvocation",
    "ExtensionPhase",
    "ExtensionPin",
    "ExtensionProtocolError",
    "ExtensionProtocol",
    "ExtensionRequest",
    "ExtensionResult",
    "ExtensionResultTooLarge",
    "ExtensionSandboxUnavailable",
    "ExtensionStatus",
    "canonical_contribution_material",
    "contribution_record",
    "discover_extensions",
    "invoke_extension",
    "select_extension",
]
