from __future__ import annotations

from pathlib import Path

import pytest
from test_w5_policy_compiler import _context, _source, _write

from outctl.control.policy import PolicyCompileError, compile_policy_source
from outctl.extensions import (
    ExtensionContext,
    ExtensionInvocation,
    ExtensionKind,
    ExtensionPhase,
    ExtensionPin,
    ExtensionRequest,
    ExtensionResult,
    ExtensionStatus,
    contribution_record,
)

DIGEST = "sha256:" + "d" * 64


def _write_policy(root: Path) -> None:
    _write(root, _source())


def _contribution(extension_id: str, value: str):
    pin = ExtensionPin(
        extension_id,
        f"package-{extension_id}",
        "1.0.0",
        f"plugin_{extension_id.replace('-', '_')}:extension",
        DIGEST,
    )
    request = ExtensionRequest(
        extension_id,
        ExtensionContext(
            "workspace-1",
            "session-1",
            None,
            1_000,
            ExtensionPhase.COMMISSIONING,
            DIGEST,
        ),
        {},
        4_096,
    )
    invocation = ExtensionInvocation(pin, request)
    return contribution_record(
        invocation,
        ExtensionResult.accepted(
            request,
            ExtensionKind.FACTS,
            {"facts": {"observed_value": value}},
        ),
    )


def test_extension_facts_bind_source_and_policy_identity_deterministically(
    tmp_path: Path,
) -> None:
    _write_policy(tmp_path)
    first = _contribution("extension-a", "one")
    second = _contribution("extension-b", "two")

    baseline = compile_policy_source(tmp_path, "policy.yaml", _context())
    empty = compile_policy_source(tmp_path, "policy.yaml", _context(), extension_contributions=())
    ordered = compile_policy_source(
        tmp_path,
        "policy.yaml",
        _context(),
        extension_contributions=(first, second),
    )
    reversed_order = compile_policy_source(
        tmp_path,
        "policy.yaml",
        _context(),
        extension_contributions=(second, first),
    )
    changed = compile_policy_source(
        tmp_path,
        "policy.yaml",
        _context(),
        extension_contributions=(_contribution("extension-a", "changed"), second),
    )

    assert empty == baseline
    assert ordered == reversed_order
    assert ordered.snapshot.source_digest != baseline.snapshot.source_digest
    assert ordered.snapshot.source_digest != changed.snapshot.source_digest
    assert ordered.snapshot.binding.digest != changed.snapshot.binding.digest
    assert ordered.snapshot.binding.snapshot_id != changed.snapshot.binding.snapshot_id
    assert ordered.snapshot.command_scope == baseline.snapshot.command_scope
    assert ordered.snapshot.sinks == baseline.snapshot.sinks
    assert ordered.snapshot.capture_commitment == baseline.snapshot.capture_commitment


def test_duplicate_or_nonaccepted_extension_contributions_fail_closed(
    tmp_path: Path,
) -> None:
    _write_policy(tmp_path)
    contribution = _contribution("extension-a", "one")
    with pytest.raises(PolicyCompileError, match="invalid"):
        compile_policy_source(
            tmp_path,
            "policy.yaml",
            _context(),
            extension_contributions=(contribution, contribution),
        )

    failed = contribution_record(
        ExtensionInvocation(
            contribution.pin,
            ExtensionRequest(
                contribution.pin.extension_id,
                ExtensionContext(
                    "workspace-1",
                    "session-1",
                    None,
                    1_000,
                    ExtensionPhase.COMMISSIONING,
                    DIGEST,
                ),
                {},
                4_096,
            ),
        ),
        ExtensionResult(
            contribution.pin.extension_id,
            ExtensionStatus.FAILED,
            diagnostics=("extension-diagnostic",),
            max_bytes=4_096,
        ),
    )
    with pytest.raises(PolicyCompileError, match="only commissioned extension facts"):
        compile_policy_source(
            tmp_path,
            "policy.yaml",
            _context(),
            extension_contributions=(failed,),
        )
