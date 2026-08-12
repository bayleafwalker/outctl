from __future__ import annotations

import importlib
import json
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).parents[1]
BUILD = ROOT / "scripts/build_hybrid_bundle.py"
CHECK = ROOT / "scripts/check_hybrid_bundle.py"


def _wheel(
    root: Path,
    filename: str,
    *,
    name: str,
    version: str,
    requirements: tuple[str, ...] = (),
) -> Path:
    path = root / filename
    metadata = ["Metadata-Version: 2.3", f"Name: {name}", f"Version: {version}"]
    metadata.extend(f"Requires-Dist: {requirement}" for requirement in requirements)
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{dist_info}/METADATA", "\n".join(metadata) + "\n\n")
        archive.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
    return path


def _capabilities(
    *, platform: str = "linux-x86_64", max_capture: int = 268_435_456
) -> dict[str, Any]:
    return {
        "schema_version": "vuoro.outctl.engine-capabilities/v2",
        "engine": {"id": "rust-w7-storage", "version": "0.1.0", "platform": platform},
        "contract_versions": {
            "run_request": ["v2"],
            "policy_snapshot": ["v2"],
            "run_result": ["v2"],
            "capture_manifest": ["v1alpha1", "v2"],
        },
        "features": {
            "direct_argv": True,
            "explicit_shell": True,
            "stdin": True,
            "retrieval": True,
            "one_version_back_read": True,
            "pty": False,
            "live_output": False,
            "parent_shell_state": False,
        },
        "limits": {
            "max_argv_items": 256,
            "max_capture_bytes": max_capture,
            "max_projection_bytes": 65_536,
        },
    }


def _native(
    root: Path, name: str, capabilities: dict[str, Any], marker: Path | None = None
) -> Path:
    path = root / name
    marker_statement = ""
    if marker is not None:
        marker_statement = f"Path({str(marker)!r}).write_text('probed', encoding='utf-8')\n"
    script = (
        f"#!{sys.executable}\n"
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"{marker_statement}"
        "if sys.argv[1:] != ['capabilities', '--json']:\n"
        "    raise SystemExit(91)\n"
        f"print(json.dumps({capabilities!r}, sort_keys=True, separators=(',', ':')))\n"
    )
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    return path


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    main = _wheel(
        tmp_path,
        "outctl-0.1.0.dev0-py3-none-any.whl",
        name="outctl",
        version="0.1.0.dev0",
        requirements=("dep-one>=1",),
    )
    dependency = _wheel(
        tmp_path,
        "dep_one-1.2.3-py3-none-any.whl",
        name="dep-one",
        version="1.2.3",
    )
    native = _native(tmp_path, "outctl-native", _capabilities())
    return main, dependency, native


def _build_command(
    destination: Path,
    main: Path,
    dependency: Path,
    native: Path,
    *,
    host: str = "linux-x86_64",
) -> list[str]:
    return [
        sys.executable,
        str(BUILD),
        "--release",
        "outctl-w8-test",
        "--version",
        "release-0.1.0",
        "--repository-commit",
        "017f3d2a6bdec77db1a843fc10b13aba3779f97a",
        "--wheel",
        str(main),
        "--native",
        f"{host}={native}",
        "--python-dependency",
        f"{host}={dependency}",
        "--destination",
        str(destination),
    ]


def _run_build(
    destination: Path,
    main: Path,
    dependency: Path,
    native: Path,
    *,
    host: str = "linux-x86_64",
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _build_command(destination, main, dependency, native, host=host),
        check=check,
        capture_output=True,
        text=True,
    )


def _check(
    bundle: Path, *, succeeds: bool, manifest_sha256: str | None = None
) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(CHECK), str(bundle)]
    if manifest_sha256 is not None:
        command.extend(["--manifest-sha256", manifest_sha256])
    return subprocess.run(
        command,
        check=succeeds,
        capture_output=True,
        text=True,
    )


def _rewrite_manifest(bundle: Path, mutate: Any) -> None:
    path = bundle / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutate(manifest)
    path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def test_builds_and_checks_canonical_host_bound_bundle_without_checker_execution(
    tmp_path: Path,
) -> None:
    main, dependency, _ = _inputs(tmp_path)
    marker = tmp_path / "probe-marker"
    native = _native(tmp_path, "marked-native", _capabilities(), marker)
    bundle = tmp_path / "bundle"

    built = _run_build(bundle, main, dependency, native)

    assert marker.read_text(encoding="utf-8") == "probed"
    marker.unlink()
    checked = _check(bundle, succeeds=True)
    assert not marker.exists(), "the read-only checker must not execute the native artifact"
    manifest_raw = (bundle / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    schema = json.loads((ROOT / "schemas/hybrid-release.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(manifest)
    build_report = json.loads(built.stdout)
    check_report = json.loads(checked.stdout)
    assert built.stdout == checked.stdout
    assert list(check_report) == [
        "host_classes",
        "manifest_sha256",
        "release_id",
        "release_version",
        "repository_commit",
        "schema_version",
    ]
    assert check_report == {
        "schema_version": "outctl.hybrid-bundle-check/v1",
        "release_id": "outctl-w8-test",
        "release_version": "release-0.1.0",
        "repository_commit": "017f3d2a6bdec77db1a843fc10b13aba3779f97a",
        "manifest_sha256": build_report["manifest_sha256"],
        "host_classes": ["linux-x86_64"],
    }
    assert manifest_raw == (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    assert manifest["schema_version"] == "outctl.hybrid-release/v1"
    assert manifest["release"]["version"] == "release-0.1.0"
    assert manifest["release"]["repository_commit"] == ("017f3d2a6bdec77db1a843fc10b13aba3779f97a")
    assert manifest["python"]["version"] == "0.1.0.dev0"
    native_entry = manifest["native"][0]
    assert native_entry["engine"]["version"] == "0.1.0"
    assert native_entry["python_dependencies"][0]["path"] == (
        "artifacts/python-dependencies/linux-x86_64/dep_one-1.2.3-py3-none-any.whl"
    )
    assert (bundle / native_entry["path"]).stat().st_mode & 0o777 == 0o755
    assert (bundle / manifest["python"]["path"]).stat().st_mode & 0o777 == 0o644


def test_checker_rejects_unmanifested_wheel_and_directory(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    bundle = tmp_path / "bundle"
    _run_build(bundle, main, dependency, native)
    injected = bundle / "artifacts/python-dependencies/linux-x86_64/injected-9-py3-none-any.whl"
    injected.write_bytes(b"not trusted")

    failed = _check(bundle, succeeds=False)
    assert failed.returncode != 0
    assert "unmanifested file" in failed.stderr

    injected.unlink()
    (bundle / "artifacts/python-dependencies/linux-x86_64/extra").mkdir()
    directory_failure = _check(bundle, succeeds=False)
    assert directory_failure.returncode != 0
    assert "unmanifested directory" in directory_failure.stderr


def test_checker_accepts_trusted_manifest_pin_and_rejects_mismatch(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    bundle = tmp_path / "bundle"
    built = _run_build(bundle, main, dependency, native)
    digest = json.loads(built.stdout)["manifest_sha256"]

    matched = _check(bundle, succeeds=True, manifest_sha256=digest)
    assert json.loads(matched.stdout)["manifest_sha256"] == digest
    _check(bundle, succeeds=True, manifest_sha256=digest.removeprefix("sha256:"))
    mismatched = _check(bundle, succeeds=False, manifest_sha256="0" * 64)
    assert mismatched.returncode != 0
    assert "does not match" in mismatched.stderr


@pytest.mark.parametrize("member", ["python", "native", "capabilities", "dependency"])
def test_checker_rejects_content_tampering(tmp_path: Path, member: str) -> None:
    main, dependency, native = _inputs(tmp_path)
    bundle = tmp_path / "bundle"
    _run_build(bundle, main, dependency, native)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    paths = {
        "python": manifest["python"]["path"],
        "native": manifest["native"][0]["path"],
        "capabilities": manifest["native"][0]["capabilities"]["path"],
        "dependency": manifest["native"][0]["python_dependencies"][0]["path"],
    }
    with (bundle / paths[member]).open("ab") as artifact:
        artifact.write(b"tamper")

    failed = _check(bundle, succeeds=False)
    assert failed.returncode != 0
    assert "drift" in failed.stderr


def test_builder_and_checker_reject_symlinks(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    linked_main = tmp_path / "linked-outctl-0.1.0.dev0-py3-none-any.whl"
    linked_main.symlink_to(main)
    failed = _run_build(tmp_path / "not-built", linked_main, dependency, native, check=False)
    assert failed.returncode != 0
    assert "non-symlink" in failed.stderr

    bundle = tmp_path / "bundle"
    _run_build(bundle, main, dependency, native)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    dependency_path = bundle / manifest["native"][0]["python_dependencies"][0]["path"]
    saved = dependency_path.with_suffix(".saved")
    dependency_path.rename(saved)
    dependency_path.symlink_to(saved)
    failed_check = _check(bundle, succeeds=False)
    assert failed_check.returncode != 0
    assert "safely read" in failed_check.stderr


def test_rejects_host_traversal_duplicate_and_unknown_dependency_host(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    invalid_commit_command = _build_command(tmp_path / "invalid-commit", main, dependency, native)
    commit_position = invalid_commit_command.index("--repository-commit") + 1
    invalid_commit_command[commit_position] = "not-a-full-commit"
    invalid_commit = subprocess.run(
        invalid_commit_command, check=False, capture_output=True, text=True
    )
    assert invalid_commit.returncode != 0
    assert "repository commit" in invalid_commit.stderr

    oversized = tmp_path / "oversized.whl"
    with oversized.open("wb") as stream:
        stream.truncate(512 * 1024 * 1024 + 1)
    oversized_command = _build_command(tmp_path / "oversized-bundle", oversized, dependency, native)
    oversized_result = subprocess.run(
        oversized_command, check=False, capture_output=True, text=True
    )
    assert oversized_result.returncode != 0
    assert "per-artifact bound" in oversized_result.stderr

    traversal = _run_build(
        tmp_path / "traversal", main, dependency, native, host="../linux", check=False
    )
    assert traversal.returncode != 0
    assert "host class" in traversal.stderr

    duplicate_command = _build_command(tmp_path / "duplicate", main, dependency, native)
    native_position = duplicate_command.index("--python-dependency")
    duplicate_command[native_position:native_position] = [
        "--native",
        f"linux-x86_64={native}",
    ]
    duplicate = subprocess.run(duplicate_command, check=False, capture_output=True, text=True)
    assert duplicate.returncode != 0
    assert "duplicate native host class" in duplicate.stderr

    unknown_command = _build_command(tmp_path / "unknown", main, dependency, native)
    unknown_command[unknown_command.index(f"linux-x86_64={dependency}")] = (
        f"other-host={dependency}"
    )
    unknown = subprocess.run(unknown_command, check=False, capture_output=True, text=True)
    assert unknown.returncode != 0
    assert "unknown native host class" in unknown.stderr


def test_copy_enforces_exact_remaining_aggregate_bound_before_staging(
    tmp_path: Path,
) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        builder = importlib.import_module("build_hybrid_bundle")
    finally:
        sys.path.pop(0)
    source = tmp_path / "source"
    source.write_bytes(b"12345")
    exact_stage = tmp_path / "exact-stage"
    exact_stage.mkdir()
    copied = builder._copy_input(
        source,
        exact_stage,
        "artifact",
        mode=0o644,
        remaining=5,
    )
    assert copied.size == 5

    rejected_stage = tmp_path / "rejected-stage"
    rejected_stage.mkdir()
    with pytest.raises(builder.BundleError, match="remaining aggregate"):
        builder._copy_input(
            source,
            rejected_stage,
            "artifact",
            mode=0o644,
            remaining=4,
        )
    assert not (rejected_stage / "artifact").exists()


def test_checker_rejects_traversal_and_duplicate_manifest_identity(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    traversal_bundle = tmp_path / "traversal-bundle"
    _run_build(traversal_bundle, main, dependency, native)
    _rewrite_manifest(
        traversal_bundle,
        lambda manifest: manifest["native"][0].update({"path": "../outctl-native"}),
    )
    traversal = _check(traversal_bundle, succeeds=False)
    assert traversal.returncode != 0
    assert "normalized bundle-relative path" in traversal.stderr

    duplicate_bundle = tmp_path / "duplicate-bundle"
    _run_build(duplicate_bundle, main, dependency, native)

    def duplicate_entry(manifest: dict[str, Any]) -> None:
        manifest["native"].append(manifest["native"][0])

    _rewrite_manifest(duplicate_bundle, duplicate_entry)
    duplicate = _check(duplicate_bundle, succeeds=False)
    assert duplicate.returncode != 0
    assert "duplicate native host class or name" in duplicate.stderr


def test_rejects_dependency_filename_and_project_collisions(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    duplicate_filename_command = _build_command(
        tmp_path / "filename-collision", main, dependency, native
    )
    dependency_option = duplicate_filename_command.index("--python-dependency")
    duplicate_filename_command[dependency_option:dependency_option] = [
        "--python-dependency",
        f"linux-x86_64={dependency}",
    ]
    filename_collision = subprocess.run(
        duplicate_filename_command, check=False, capture_output=True, text=True
    )
    assert filename_collision.returncode != 0
    assert "duplicate dependency wheel filename" in filename_collision.stderr

    alias = _wheel(
        tmp_path,
        "dep_one-1.2.3-1-py3-none-any.whl",
        name="dep.one",
        version="1.2.3",
    )
    duplicate_project_command = _build_command(
        tmp_path / "project-collision", main, dependency, native
    )
    dependency_option = duplicate_project_command.index("--python-dependency")
    duplicate_project_command[dependency_option:dependency_option] = [
        "--python-dependency",
        f"linux-x86_64={alias}",
    ]
    project_collision = subprocess.run(
        duplicate_project_command, check=False, capture_output=True, text=True
    )
    assert project_collision.returncode != 0
    assert "duplicate Python project name" in project_collision.stderr


def test_rejects_incomplete_host_dependency_set(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    unrelated = _wheel(
        tmp_path,
        "unrelated-1.0-py3-none-any.whl",
        name="unrelated",
        version="1.0",
    )
    failed = _run_build(tmp_path / "bundle", main, unrelated, native, check=False)
    assert failed.returncode != 0
    assert "incomplete" in failed.stderr
    assert "dep-one" in failed.stderr


def test_rejects_cross_host_capability_mismatch_atomically(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    second_native = _native(
        tmp_path,
        "outctl-native-other",
        _capabilities(platform="linux-aarch64", max_capture=1024),
    )
    destination = tmp_path / "bundle"
    command = _build_command(destination, main, dependency, native)
    command.extend(
        [
            "--native",
            f"linux-aarch64={second_native}",
            "--python-dependency",
            f"linux-aarch64={dependency}",
        ]
    )
    failed = subprocess.run(command, check=False, capture_output=True, text=True)
    assert failed.returncode != 0
    assert "mismatched capabilities" in failed.stderr
    assert not destination.exists()


def test_rejects_any_preexisting_destination_and_mode_drift(tmp_path: Path) -> None:
    main, dependency, native = _inputs(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    empty_failure = _run_build(empty, main, dependency, native, check=False)
    assert empty_failure.returncode != 0
    assert "any pre-existing destination" in empty_failure.stderr
    assert empty.is_dir()

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("owned", encoding="utf-8")
    failed = _run_build(occupied, main, dependency, native, check=False)
    assert failed.returncode != 0
    assert "any pre-existing destination" in failed.stderr
    assert (occupied / "keep").read_text(encoding="utf-8") == "owned"

    bundle = tmp_path / "bundle"
    _run_build(bundle, main, dependency, native)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    native_path = bundle / manifest["native"][0]["path"]
    native_path.chmod(0o755 & ~stat.S_IXUSR)
    mode_failure = _check(bundle, succeeds=False)
    assert mode_failure.returncode != 0
    assert "mode drift" in mode_failure.stderr

    native_path.chmod(0o755)
    bundle.chmod(0o775)
    writable_root = _check(bundle, succeeds=False)
    assert writable_root.returncode != 0
    assert "group/world writable" in writable_root.stderr
