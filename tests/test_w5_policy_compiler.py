from __future__ import annotations

import hashlib
import json
import pickle
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from outctl.control import (
    ClaimProvenance,
    CommissioningContext,
    PolicyCompileError,
    PolicySourcePathError,
    ProtectedSecretRegistry,
    SecretRegistryError,
    canonical_policy_material,
    commissioning_provenance_digest,
    compile_policy_source,
    explain_policy,
    lint_policy_source,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _context(
    trust_domain: str = "trusted-local",
    commissioned: bool = True,
    *,
    claims_reversed: bool = False,
) -> CommissioningContext:
    claims = (
        ClaimProvenance("trust_domain", trust_domain, "host-policy", "audit://trust/1", DIGEST_A),
        ClaimProvenance(
            "commissioned", commissioned, "host-policy", "audit://commission/1", DIGEST_B
        ),
    )
    return CommissioningContext(
        session_id="session-1",
        trust_domain=trust_domain,
        commissioned=commissioned,
        issued_at="2026-08-12T08:00:00+00:00",
        valid_for_ms=3_600_000,
        claims=tuple(reversed(claims)) if claims_reversed else claims,
    )


def _sink(
    name: str = "model",
    trust_domain: str = "trusted-local",
    disclosure: str = "safe-unredacted",
    redaction_required: bool = False,
) -> dict[str, object]:
    return {
        "name": name,
        "trust_domain": trust_domain,
        "disclosure": disclosure,
        "redaction_required": redaction_required,
        "classification_ceiling": "secret",
    }


def _source(*sinks: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "vuoro.outctl.policy-source/v1",
        "policy_ref": "policy://test-w5",
        "cache": {"max_age_ms": 1_800_000},
        "sinks": list(sinks or (_sink(),)),
        "capture": {
            "commitment": "host-persistent",
            "durability": "host",
            "required": True,
        },
    }


def _write(root: Path, value: dict[str, object], name: str = "policy.yaml") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def _canonical_digest(value: object) -> str:
    body = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def test_trusted_local_compiles_safe_unredacted_with_pinned_identity(tmp_path: Path) -> None:
    _write(tmp_path, _source())
    compiled = compile_policy_source(tmp_path, "policy.yaml", _context())
    snapshot = compiled.snapshot

    assert snapshot.sinks[0].disclosure == "safe-unredacted"
    assert snapshot.capture_required
    assert snapshot.binding.snapshot_id == "snapshot-" + snapshot.binding.digest[7:39]
    assert snapshot.cache.key.endswith(snapshot.binding.snapshot_id)
    assert snapshot.to_dict()["execution_authority"] == {
        "owner": "external-runner",
        "can_authorize_execution": False,
        "can_retry": False,
    }
    assert snapshot.binding.digest == _canonical_digest(canonical_policy_material(snapshot))
    assert snapshot.command_scope.execution_modes == ("direct-argv",)
    assert snapshot.command_scope.stdin_modes == ("none",)


def test_w6_command_scope_is_exactly_compiled_and_digest_bound(tmp_path: Path) -> None:
    direct = _source()
    _write(tmp_path, direct)
    baseline = compile_policy_source(tmp_path, "policy.yaml", _context())

    scoped = _source()
    scoped["command_scope"] = {
        "execution_modes": ["direct-argv", "explicit-shell"],
        "explicit_shell_argv": [["/bin/sh", "-c"]],
        "stdin_modes": ["none", "file-ref"],
    }
    _write(tmp_path, scoped)
    compiled = compile_policy_source(tmp_path, "policy.yaml", _context())
    assert compiled.snapshot.command_scope.explicit_shell_argv == (("/bin/sh", "-c"),)
    assert compiled.snapshot.command_scope.stdin_modes == ("none", "file-ref")
    assert compiled.snapshot.binding.digest != baseline.snapshot.binding.digest

    for invalid_scope in (
        {
            "execution_modes": ["direct-argv", "explicit-shell"],
            "explicit_shell_argv": [],
            "stdin_modes": ["none"],
        },
        {
            "execution_modes": ["direct-argv", "explicit-shell"],
            "explicit_shell_argv": [["sh", "-c"]],
            "stdin_modes": ["none"],
        },
        {
            "execution_modes": ["direct-argv"],
            "explicit_shell_argv": [["/bin/sh", "-c"]],
            "stdin_modes": ["none"],
        },
        {
            "execution_modes": ["direct-argv"],
            "explicit_shell_argv": [],
            "stdin_modes": ["file-ref"],
        },
    ):
        invalid = _source()
        invalid["command_scope"] = invalid_scope
        _write(tmp_path, invalid)
        with pytest.raises(PolicyCompileError, match="command_scope"):
            compile_policy_source(tmp_path, "policy.yaml", _context())


def test_restricted_policy_is_sanitized_and_author_order_is_canonical(tmp_path: Path) -> None:
    sinks = (
        _sink("handoff", "export", "sanitized", True),
        _sink("model", "restricted", "sanitized", True),
    )
    _write(tmp_path, _source(*sinks))
    first = compile_policy_source(tmp_path, "policy.yaml", _context("restricted", False))
    _write(tmp_path, _source(*reversed(sinks)))
    second = compile_policy_source(
        tmp_path, "policy.yaml", _context("restricted", False, claims_reversed=True)
    )

    assert [sink.name for sink in first.snapshot.sinks] == ["handoff", "model"]
    assert first.snapshot == second.snapshot
    assert first.provenance == second.provenance


@pytest.mark.parametrize(
    ("context_domain", "sink"),
    [
        ("export", _sink("handoff", "export", "sanitized", True)),
        ("export", _sink("audit-receipt", "metadata-only", "metadata-only", True)),
        ("metadata-only", _sink("runner", "metadata-only", "metadata-only", True)),
        ("restricted", _sink("model", "restricted", "deny", True)),
    ],
)
def test_export_metadata_only_and_deny_actions_compile(
    tmp_path: Path, context_domain: str, sink: dict[str, object]
) -> None:
    _write(tmp_path, _source(sink))
    compiled = compile_policy_source(tmp_path, "policy.yaml", _context(context_domain, False))
    assert compiled.snapshot.sinks[0].disclosure == sink["disclosure"]


def test_downgrade_and_trusted_capture_weakening_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path, _source(_sink("model", "trusted-local", "safe-unredacted", False)))
    with pytest.raises(PolicyCompileError, match="widen"):
        compile_policy_source(tmp_path, "policy.yaml", _context("restricted", False))

    weak = _source()
    weak["capture"] = {"commitment": "process-local", "durability": "none", "required": False}
    _write(tmp_path, weak)
    with pytest.raises(PolicyCompileError, match="persistent required"):
        compile_policy_source(tmp_path, "policy.yaml", _context())


def test_claims_are_explicit_consistent_deterministic_and_bound_to_source_digest(
    tmp_path: Path,
) -> None:
    _write(tmp_path, _source())
    first_context = _context()
    second_context = _context(claims_reversed=True)
    first = compile_policy_source(tmp_path, "policy.yaml", first_context)
    second = compile_policy_source(tmp_path, "policy.yaml", second_context)
    assert first == second
    assert first.provenance.digest == commissioning_provenance_digest(first_context)

    changed_claim = replace(first_context.claims[0], evidence_digest="sha256:" + "c" * 64)
    changed_context = replace(first_context, claims=(changed_claim, first_context.claims[1]))
    changed = compile_policy_source(tmp_path, "policy.yaml", changed_context)
    assert changed.snapshot.source_digest != first.snapshot.source_digest
    assert changed.snapshot.binding.digest != first.snapshot.binding.digest

    with pytest.raises(PolicyCompileError, match="contradicts"):
        replace(
            first_context,
            claims=(replace(first_context.claims[0], value="restricted"), first_context.claims[1]),
        )


def test_source_loading_rejects_traversal_absolute_paths_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = _write(tmp_path, _source(), "outside.yaml")
    (root / "linked.yaml").symlink_to(outside)
    linked_dir = root / "linked-dir"
    linked_dir.symlink_to(tmp_path, target_is_directory=True)

    for unsafe in ("../outside.yaml", outside, "linked.yaml", "linked-dir/outside.yaml"):
        with pytest.raises(PolicySourcePathError):
            compile_policy_source(root, unsafe, _context())


def test_strict_unknown_keys_types_duplicates_bounds_and_sink_targets(tmp_path: Path) -> None:
    invalid_documents = []
    unknown = _source()
    unknown["secret_value"] = "must-never-appear"
    invalid_documents.append(unknown)
    wrong_type = _source()
    wrong_type["cache"] = {"max_age_ms": True}
    invalid_documents.append(wrong_type)
    too_old = _source()
    too_old["cache"] = {"max_age_ms": 3_600_001}
    invalid_documents.append(too_old)
    duplicate = _source(_sink("model"), _sink("model", "restricted", "sanitized", True))
    invalid_documents.append(duplicate)
    unsupported = _source(_sink("telemetry", "restricted", "sanitized", True))
    invalid_documents.append(unsupported)

    for document in invalid_documents:
        _write(tmp_path, document)
        with pytest.raises(PolicyCompileError):
            compile_policy_source(tmp_path, "policy.yaml", _context())

    (tmp_path / "policy.yaml").write_text(
        "schema_version: vuoro.outctl.policy-source/v1\n"
        "policy_ref: policy://one\npolicy_ref: policy://two\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyCompileError, match="duplicate"):
        compile_policy_source(tmp_path, "policy.yaml", _context())


def test_secret_registry_values_never_serialize_or_leak_from_explain_and_lint(
    tmp_path: Path,
) -> None:
    exact = "w5-super-secret-value"
    registry = ProtectedSecretRegistry()
    registry.register("secret://request/token", exact)
    assert registry.resolve("secret://request/token") == exact.encode()
    assert exact not in repr(registry)
    assert registry.refs == ("secret://request/token",)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(registry)
    with pytest.raises(SecretRegistryError) as duplicate:
        registry.register("secret://request/token", exact)
    assert exact not in str(duplicate.value)

    _write(tmp_path, _source())
    compiled = compile_policy_source(tmp_path, "policy.yaml", _context())
    rendered = json.dumps(explain_policy(compiled).to_dict(), sort_keys=True)
    assert exact not in rendered
    assert "value" not in rendered
    assert compiled.provenance.digest in rendered

    poisoned = _source()
    poisoned["unknown"] = exact
    _write(tmp_path, poisoned)
    lint = lint_policy_source(tmp_path, "policy.yaml", _context())
    assert not lint.valid
    assert exact not in json.dumps(lint.to_dict())

    registry.unregister("secret://request/token")
    with pytest.raises(SecretRegistryError):
        registry.resolve("secret://request/token")


def test_secret_registry_rejects_secret_refs_as_claim_evidence() -> None:
    with pytest.raises(PolicyCompileError):
        ClaimProvenance("commissioned", True, "host-policy", "secret://request/token", DIGEST_A)
