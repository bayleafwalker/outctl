"""Bounded Kubernetes facts/projection example; it owns no kubectl authority."""

from __future__ import annotations

from outctl.extensions.contracts import (
    ExtensionKind,
    ExtensionPhase,
    ExtensionRequest,
    ExtensionResult,
)


def extension(request: ExtensionRequest) -> ExtensionResult:
    resources = request.input.get("resources", [])
    if not isinstance(resources, list) or not all(
        isinstance(item, str) and 0 < len(item) <= 128 for item in resources
    ):
        return ExtensionResult.failed(request)
    normalized = sorted(set(resources))[:64]
    if request.context.phase is ExtensionPhase.COMMISSIONING:
        return ExtensionResult.accepted(
            request,
            ExtensionKind.FACTS,
            {"facts": {"command_family": "kubernetes", "resources": normalized}},
        )
    return ExtensionResult.accepted(
        request,
        ExtensionKind.PROJECTION_CANDIDATE,
        {
            "title": "Kubernetes resources",
            "lines": [f"resource/{name}" for name in normalized],
            "lossy": len(resources) > len(normalized),
        },
    )


__all__ = ["extension"]
