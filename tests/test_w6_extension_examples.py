from __future__ import annotations

from pathlib import Path

import pytest
from test_w6_extension_support import install_example_distribution

from outctl.extensions import (
    ExtensionContext,
    ExtensionInvocation,
    ExtensionKind,
    ExtensionPhase,
    ExtensionRequest,
    ExtensionStatus,
    discover_extensions,
    invoke_extension,
)

ROOT = Path(__file__).parents[1]
DIGEST = "sha256:" + "d" * 64


@pytest.mark.parametrize(
    ("name", "input_value", "expected_id"),
    [
        ("kubernetes", {"resources": ["pods", "deployments", "pods"]}, "kubernetes"),
        ("custom", {"labels": ["zeta", "alpha", "alpha"]}, "custom-summary"),
    ],
)
def test_separately_packaged_examples_use_only_generic_entry_point_path(
    tmp_path: Path,
    name: str,
    input_value: dict[str, object],
    expected_id: str,
) -> None:
    example = ROOT / "examples" / "extensions" / name
    site = install_example_distribution(tmp_path, example)
    discovered = discover_extensions([site])
    assert len(discovered) == 1
    assert discovered[0].pin.extension_id == expected_id
    invocation = ExtensionInvocation(
        discovered[0].pin,
        ExtensionRequest(
            expected_id,
            ExtensionContext(
                "workspace-1",
                "session-1",
                None,
                2_000,
                ExtensionPhase.COMMISSIONING,
                DIGEST,
            ),
            input_value,
            4_096,
        ),
    )
    result = invoke_extension(invocation, plugin_roots=(site,))
    assert result.status is ExtensionStatus.ACCEPTED
    assert result.kind is ExtensionKind.FACTS
    assert "authorize" not in repr(result.payload).casefold()

    projection = ExtensionInvocation(
        discovered[0].pin,
        ExtensionRequest(
            expected_id,
            ExtensionContext(
                "workspace-1",
                "session-1",
                "snapshot-1",
                2_000,
                ExtensionPhase.PROJECTION,
                None,
                "policy://example",
                DIGEST,
            ),
            input_value,
            4_096,
        ),
    )
    projected = invoke_extension(projection, plugin_roots=(site,))
    assert projected.status is ExtensionStatus.ACCEPTED
    assert projected.kind is ExtensionKind.PROJECTION_CANDIDATE
    assert set(projected.payload) == {"title", "lines", "lossy"}
