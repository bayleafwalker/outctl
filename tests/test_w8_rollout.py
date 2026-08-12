from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path

import jsonschema
import pytest

from outctl.control import CapabilityRequirement, EngineFeature
from outctl.native import EngineChoice, NativeEngineUnavailable
from outctl.native.rollout import (
    HostArtifactPin,
    HostClass,
    RolloutEvidence,
    RolloutEvidenceError,
    RolloutMode,
    RolloutTrack,
    WaveGate,
    canonical_json_digest,
    cohort_bucket,
    run_pinned_native,
    select_rollout_engines,
)

HOST = HostClass("linux", "x86_64", "glibc", "cp312")
COMMIT = "a" * 40
ROOT = Path(__file__).parents[1]


def _capabilities(*, explicit_shell: bool = True) -> dict[str, object]:
    return {
        "schema_version": "vuoro.outctl.engine-capabilities/v2",
        "engine": {
            "id": "rust-w7-storage",
            "version": "0.1.0",
            "platform": "linux-x86_64",
        },
        "contract_versions": {
            "run_request": ["v2"],
            "policy_snapshot": ["v2"],
            "run_result": ["v2"],
            "capture_manifest": ["v1alpha1", "v2"],
        },
        "features": {
            "direct_argv": True,
            "explicit_shell": explicit_shell,
            "stdin": True,
            "retrieval": True,
            "one_version_back_read": True,
            "pty": False,
            "live_output": False,
            "parent_shell_state": False,
        },
        "limits": {
            "max_argv_items": 256,
            "max_capture_bytes": 268_435_456,
            "max_projection_bytes": 65_536,
        },
    }


def _native(tmp_path: Path, document: dict[str, object] | None = None) -> Path:
    document = _capabilities() if document is None else document
    executable = tmp_path / "outctl-native"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json,sys\n"
        f"DOC={document!r}\n"
        "assert sys.argv[1:] == ['capabilities', '--json']\n"
        "print(json.dumps(DOC, sort_keys=True, separators=(',', ':')))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _evidence(
    native: Path,
    *,
    capabilities: dict[str, object] | None = None,
    clean_install: bool = True,
    host_conformance: bool = True,
    shadow: bool = True,
    rollback: bool = True,
    canary: bool = False,
    canary_basis_points: int = 10_000,
    native_default: bool = False,
) -> RolloutEvidence:
    document = _capabilities() if capabilities is None else capabilities
    return RolloutEvidence(
        release_manifest_digest="sha256:" + "b" * 64,
        repository_commit=COMMIT,
        host_artifacts=(
            HostArtifactPin(HOST.identifier, _sha256(native), canonical_json_digest(document)),
        ),
        prior_waves=tuple(
            WaveGate(wave, f"{wave + 1:040x}", (f"w{wave}-gate",)) for wave in range(8)
        ),
        clean_install_passed=clean_install,
        host_conformance_passed=host_conformance,
        shadow_passed=shadow,
        rollback_passed=rollback,
        canary_passed=canary,
        evidence_ids=("bundle", "install", "conformance", "rollback"),
        canary_basis_points=canary_basis_points,
        native_default_enabled=native_default,
        native_default_authorization="owner:change-42" if native_default else None,
    )


def test_bypass_is_unconditional_and_never_probes_native(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    evidence = _evidence(_native(tmp_path))
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.ENFORCE,
        host_class=HOST,
        native_executable=missing,
        environment={"OUTCTL_ENABLED": "0"},
    )
    assert selection.mode is RolloutMode.BYPASS
    assert selection.track is RolloutTrack.PYTHON
    assert selection.engine.choice is EngineChoice.PYTHON_REFERENCE
    malformed_configuration = select_rollout_engines(
        evidence,
        mode="unsupported",
        host_class=HOST,
        native_executable=missing,
        environment={"OUTCTL_ENABLED": "0", "OUTCTL_MODE": "unsupported"},
    )
    assert malformed_configuration.mode is RolloutMode.BYPASS


def test_shadow_selects_one_pinned_native_execution_and_preserves_shadow_mode(
    tmp_path: Path,
) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native, shadow=False)
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.SHADOW,
        host_class=HOST,
        native_executable=native,
        environment={},
    )
    assert selection.track is RolloutTrack.SHADOW
    assert selection.mode is RolloutMode.SHADOW
    assert selection.engine.choice is EngineChoice.RUST_NATIVE
    completed = selection.run_native(("capabilities", "--json"), timeout=5)
    assert completed.returncode == 0


def test_canary_is_stable_and_rust_is_not_the_global_default(tmp_path: Path) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native)
    first = cohort_bucket(evidence.release_manifest_digest, HOST, "runner/session/one")
    second = cohort_bucket(evidence.release_manifest_digest, HOST, "runner/session/one")
    assert first == second
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.ENFORCE,
        host_class=HOST,
        native_executable=native,
        canary_key="runner/session/one",
        environment={},
    )
    assert selection.track is RolloutTrack.CANARY
    assert selection.engine.choice is EngineChoice.RUST_NATIVE
    assert selection.cohort_bucket == first

    no_cohort = select_rollout_engines(
        evidence,
        mode=RolloutMode.ENFORCE,
        host_class=HOST,
        native_executable=native,
        environment={},
    )
    assert no_cohort.track is RolloutTrack.PYTHON


def test_outside_canary_cohort_stays_python_without_native_probe(tmp_path: Path) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native, canary_basis_points=1)
    key = next(
        f"key-{number}"
        for number in range(100)
        if cohort_bucket(evidence.release_manifest_digest, HOST, f"key-{number}") >= 1
    )
    native.unlink()
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.ENFORCE,
        host_class=HOST,
        native_executable=native,
        canary_key=key,
        environment={},
    )
    assert selection.track is RolloutTrack.PYTHON


def test_default_requires_all_gates_and_external_authorization(tmp_path: Path) -> None:
    native = _native(tmp_path)
    with pytest.raises(RolloutEvidenceError, match="authorization"):
        RolloutEvidence(
            **{
                **_evidence(native).__dict__,
                "native_default_enabled": True,
                "native_default_authorization": None,
            }
        )
    incomplete = _evidence(native, canary=False, native_default=True)
    with pytest.raises(RolloutEvidenceError, match="canary gate"):
        select_rollout_engines(
            incomplete,
            mode=RolloutMode.ENFORCE,
            host_class=HOST,
            native_executable=native,
            environment={},
        )
    complete = _evidence(native, canary=True, native_default=True)
    selection = select_rollout_engines(
        complete,
        mode=RolloutMode.ENFORCE,
        host_class=HOST,
        native_executable=native,
        environment={},
    )
    assert selection.track is RolloutTrack.NATIVE_DEFAULT


@pytest.mark.parametrize("gate", ["clean_install", "host_conformance", "rollback"])
def test_incomplete_pre_shadow_gate_keeps_python_without_native_probe(
    tmp_path: Path, gate: str
) -> None:
    native = _native(tmp_path)
    options = {gate: False}
    evidence = _evidence(native, **options)  # type: ignore[arg-type]
    native.unlink()
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.SHADOW,
        host_class=HOST,
        native_executable=native,
        environment={},
    )
    assert selection.track is RolloutTrack.PYTHON


def test_enforce_stays_python_until_shadow_gate_passes(tmp_path: Path) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native, shadow=False)
    native.unlink()
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.ENFORCE,
        host_class=HOST,
        native_executable=native,
        canary_key="candidate",
        environment={},
    )
    assert selection.track is RolloutTrack.PYTHON


def test_unknown_host_stays_python_and_does_not_probe(tmp_path: Path) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native)
    native.unlink()
    selection = select_rollout_engines(
        evidence,
        mode=RolloutMode.ENFORCE,
        host_class=HostClass("linux", "aarch64", "glibc", "cp312"),
        native_executable=native,
        canary_key="candidate",
        environment={},
    )
    assert selection.track is RolloutTrack.PYTHON


def test_native_digest_drift_fails_closed(tmp_path: Path) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native)
    native.write_text(native.read_text() + "# tampered\n")
    with pytest.raises(NativeEngineUnavailable, match="artifact"):
        select_rollout_engines(
            evidence,
            mode=RolloutMode.SHADOW,
            host_class=HOST,
            native_executable=native,
            environment={},
        )


def test_native_platform_drift_fails_closed(tmp_path: Path) -> None:
    document = _capabilities()
    engine = document["engine"]
    assert isinstance(engine, dict)
    engine["platform"] = "linux-aarch64"
    native = _native(tmp_path, document)
    evidence = _evidence(native, capabilities=document)
    with pytest.raises(NativeEngineUnavailable, match="platform"):
        select_rollout_engines(
            evidence,
            mode=RolloutMode.SHADOW,
            host_class=HOST,
            native_executable=native,
            environment={},
        )


def test_capability_negotiation_rejects_unsupported_requested_feature(tmp_path: Path) -> None:
    document = _capabilities(explicit_shell=False)
    native = _native(tmp_path, document)
    evidence = _evidence(native, capabilities=document)
    requirement = CapabilityRequirement(features=frozenset({EngineFeature.EXPLICIT_SHELL}))
    with pytest.raises(ValueError, match="explicit_shell"):
        select_rollout_engines(
            evidence,
            mode=RolloutMode.SHADOW,
            host_class=HOST,
            native_executable=native,
            requirement=requirement,
            environment={},
        )


def test_symlinked_or_non_executable_artifact_fails_closed(tmp_path: Path) -> None:
    native = _native(tmp_path)
    evidence = _evidence(native)
    link = tmp_path / "link"
    link.symlink_to(native)
    with pytest.raises(NativeEngineUnavailable, match="unsafe"):
        select_rollout_engines(
            evidence,
            mode=RolloutMode.SHADOW,
            host_class=HOST,
            native_executable=link,
            environment={},
        )
    native.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with pytest.raises(NativeEngineUnavailable, match="regular executable"):
        select_rollout_engines(
            evidence,
            mode=RolloutMode.SHADOW,
            host_class=HOST,
            native_executable=native,
            environment={},
        )
    native.chmod(0o775)
    with pytest.raises(NativeEngineUnavailable, match="group/world writable"):
        select_rollout_engines(
            evidence,
            mode=RolloutMode.SHADOW,
            host_class=HOST,
            native_executable=native,
            environment={},
        )


def test_pinned_execution_keeps_opened_inode_across_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = _native(tmp_path)
    expected = _sha256(native)
    replacement = tmp_path / "replacement"
    replacement.write_text(
        f"#!{sys.executable}\nraise SystemExit(77)\n",
        encoding="utf-8",
    )
    replacement.chmod(0o755)

    from outctl.native import rollout

    original_hash = rollout._sha256_fd

    def replace_after_hash(descriptor: int) -> str:
        result = original_hash(descriptor)
        replacement.replace(native)
        return result

    monkeypatch.setattr(rollout, "_sha256_fd", replace_after_hash)
    completed = run_pinned_native(
        native,
        expected,
        ("capabilities", "--json"),
        timeout=5,
    )
    assert completed.returncode == 0
    assert b'"rust-w7-storage"' in completed.stdout


def test_pinned_execution_preserves_caller_environment_and_cwd(tmp_path: Path) -> None:
    executable = tmp_path / "probe"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json,os\n"
        "print(json.dumps({'cwd':os.getcwd(),'value':os.environ.get('W8_VALUE')}))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    working = tmp_path / "working"
    working.mkdir()
    completed = run_pinned_native(
        executable,
        _sha256(executable),
        (),
        timeout=5,
        cwd=working,
        environment={"W8_VALUE": "preserved"},
    )
    assert json.loads(completed.stdout) == {
        "cwd": str(working),
        "value": "preserved",
    }


def test_evidence_parser_requires_exact_ordered_w0_w7() -> None:
    document: dict[str, object] = {
        "schema_version": "vuoro.outctl.w8-adoption-evidence/v1",
        "release_manifest_digest": "sha256:" + "b" * 64,
        "repository_commit": COMMIT,
        "host_artifacts": [
            {
                "host_class": HOST.identifier,
                "native_sha256": "sha256:" + "c" * 64,
                "capabilities_sha256": "sha256:" + "d" * 64,
            }
        ],
        "prior_waves": [
            {"wave": wave, "commit": f"{wave + 1:040x}", "evidence_ids": [f"w{wave}"]}
            for wave in range(7)
        ],
        "gates": {
            "clean_install_passed": True,
            "host_conformance_passed": True,
            "shadow_passed": True,
            "rollback_passed": True,
            "canary_passed": False,
        },
        "rollout": {
            "canary_basis_points": 100,
            "native_default_enabled": False,
            "native_default_authorization": None,
        },
        "evidence_ids": ["local"],
    }
    with pytest.raises(RolloutEvidenceError, match="W0-W7"):
        RolloutEvidence.from_dict(document)


def test_checked_in_adoption_example_is_schema_valid_and_fail_closed() -> None:
    document = json.loads(
        (ROOT / "config/w8-adoption-evidence.example.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (ROOT / "schemas/w8-adoption-evidence.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(document)
    evidence = RolloutEvidence.from_dict(document)
    assert not evidence.pre_shadow_passed
    assert not evidence.native_default_enabled
    document["unexpected"] = True
    with pytest.raises(RolloutEvidenceError, match="exactly"):
        RolloutEvidence.from_dict(document)
