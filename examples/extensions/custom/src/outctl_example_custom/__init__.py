"""Arbitrary third-party-style bounded projection example."""

from __future__ import annotations

from outctl.extensions.contracts import (
    ExtensionKind,
    ExtensionPhase,
    ExtensionRequest,
    ExtensionResult,
)


def extension(request: ExtensionRequest) -> ExtensionResult:
    labels = request.input.get("labels", [])
    if not isinstance(labels, list) or not all(
        isinstance(item, str) and 0 < len(item) <= 128 for item in labels
    ):
        return ExtensionResult.failed(request)
    normalized = sorted(set(labels))[:64]
    if request.context.phase is ExtensionPhase.COMMISSIONING:
        return ExtensionResult.accepted(
            request,
            ExtensionKind.FACTS,
            {"facts": {"profile": "custom-summary", "labels": normalized}},
        )
    return ExtensionResult.accepted(
        request,
        ExtensionKind.PROJECTION_CANDIDATE,
        {"title": "Custom summary", "lines": normalized, "lossy": len(labels) > len(normalized)},
    )


__all__ = ["extension"]
