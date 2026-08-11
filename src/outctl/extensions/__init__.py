"""Bounded Python extension contracts.

Extensions are adaptive inputs to commissioning or an explicitly bounded slow
path.  They never authorize execution, retry, persistence, lifecycle, or
publication, and this package contains no extension discovery or process
runner.
"""

from outctl.extensions.contracts import (
    ExtensionContext,
    ExtensionKind,
    ExtensionProtocol,
    ExtensionRequest,
    ExtensionResult,
    ExtensionResultTooLarge,
    ExtensionStatus,
)

__all__ = [
    "ExtensionContext",
    "ExtensionKind",
    "ExtensionProtocol",
    "ExtensionRequest",
    "ExtensionResult",
    "ExtensionResultTooLarge",
    "ExtensionStatus",
]
