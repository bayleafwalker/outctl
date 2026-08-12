"""Atomically assemble an unpublished, pinned Outctl hybrid release bundle.

``--version`` is the repository/release label.  It intentionally does not have
to equal either the Python wheel version or the native Cargo version during the
migration window; those artifact versions are discovered, recorded, and
verified independently.

The only artifact execution performed here is exactly
``outctl-native capabilities --json`` for each copied native variant.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import email.policy
import errno
import hashlib
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import time
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Final

from check_hybrid_bundle import (
    MAX_ARTIFACT_BYTES,
    MAX_BUNDLE_INPUT_BYTES,
    MAX_CAPABILITIES_BYTES,
    SCHEMA_VERSION,
    BundleError,
    _host_class,
    _load_json,
    _string,
    _validate_capabilities,
    _wheel_filename,
    bundle_check_report,
    canonical_json,
    capability_profile,
    check_bundle,
)

MAX_NATIVE_VARIANTS: Final = 64
MAX_DEPENDENCIES_PER_HOST: Final = 256
PROBE_TIMEOUT_SECONDS: Final = 15.0
MAX_WHEEL_METADATA_BYTES: Final = 1_048_576
RENAME_NOREPLACE: Final = 1


@dataclass(frozen=True)
class _WheelMetadata:
    name: str
    version: str
    requirements: frozenset[str]


@dataclass(frozen=True)
class _Copied:
    path: str
    sha256: str
    size: int
    mode: str

    def pin(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
        }


def _account_bundle_bytes(total: int, copied: _Copied) -> int:
    updated = total + copied.size
    if updated > MAX_BUNDLE_INPUT_BYTES:
        raise BundleError("bundle inputs exceed the aggregate byte bound")
    return updated


def _canonical_project_name(value: str, *, label: str) -> str:
    if not value or len(value) > 128:
        raise BundleError(f"{label} is empty or too long")
    normalized: list[str] = []
    previous_separator = False
    for character in value.lower():
        if character.isascii() and character.isalnum():
            normalized.append(character)
            previous_separator = False
        elif character in ".-_":
            if not previous_separator:
                normalized.append("-")
            previous_separator = True
        else:
            raise BundleError(f"{label} is not a valid Python project name")
    result = "".join(normalized).strip("-")
    if not result:
        raise BundleError(f"{label} is not a valid Python project name")
    return result


def _requirement_project(value: str, *, label: str) -> str | None:
    """Conservatively return a non-extra dependency project from Requires-Dist."""

    requirement, separator, marker = value.partition(";")
    if separator and "extra" in marker.lower():
        return None
    requirement = requirement.strip()
    end = 0
    while end < len(requirement) and (
        requirement[end].isascii() and (requirement[end].isalnum() or requirement[end] in ".-_")
    ):
        end += 1
    if end == 0:
        raise BundleError(f"{label} has an unsupported Requires-Dist value: {value!r}")
    return _canonical_project_name(requirement[:end], label=label)


def _wheel_metadata(path: Path, *, expected_main: bool = False) -> _WheelMetadata:
    filename = _wheel_filename(path.name, label=f"wheel filename {path.name!r}")
    del filename
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_members = [
                member
                for member in archive.infolist()
                if member.filename.endswith(".dist-info/METADATA")
                and len(PureParts := member.filename.split("/")) == 2
                and PureParts[0].endswith(".dist-info")
            ]
            if len(metadata_members) != 1:
                raise BundleError(
                    f"wheel {path.name!r} must contain exactly one dist-info/METADATA"
                )
            member = metadata_members[0]
            if member.file_size > MAX_WHEEL_METADATA_BYTES:
                raise BundleError(f"wheel {path.name!r} metadata exceeds its bound")
            raw = archive.read(member)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise BundleError(f"cannot read wheel metadata from {path.name!r}: {error}") from error
    if len(raw) > MAX_WHEEL_METADATA_BYTES:
        raise BundleError(f"wheel {path.name!r} metadata exceeds its bound")
    message = BytesParser(policy=email.policy.default).parsebytes(raw)
    names = message.get_all("Name", [])
    versions = message.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1:
        raise BundleError(f"wheel {path.name!r} must have exactly one Name and Version field")
    name = _canonical_project_name(str(names[0]), label=f"{path.name} metadata Name")
    version = _string(str(versions[0]), label=f"{path.name} metadata Version", maximum=128)
    filename_components = path.name.removesuffix(".whl").split("-")
    filename_project = _canonical_project_name(
        filename_components[0], label=f"{path.name} filename project"
    )
    if filename_project != name:
        raise BundleError(f"wheel {path.name!r} filename project does not match metadata Name")
    if filename_components[1] != version.replace("-", "_"):
        raise BundleError(f"wheel {path.name!r} filename version does not match metadata Version")
    if expected_main and name != "outctl":
        raise BundleError(f"main wheel project must be 'outctl', got {name!r}")
    requirements = frozenset(
        project
        for index, value in enumerate(message.get_all("Requires-Dist", []))
        if (
            project := _requirement_project(str(value), label=f"{path.name} Requires-Dist[{index}]")
        )
        is not None
    )
    return _WheelMetadata(name=name, version=version, requirements=requirements)


def _validate_source(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BundleError(f"cannot inspect input {path}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BundleError(f"input must be a regular non-symlink file: {path}")
    if metadata.st_size > MAX_ARTIFACT_BYTES:
        raise BundleError(f"input exceeds the per-artifact bound: {path}")
    return metadata


def _copy_input(
    source: Path,
    stage: Path,
    relative: str,
    *,
    mode: int,
    remaining: int,
) -> _Copied:
    before = _validate_source(source)
    if before.st_size > remaining:
        raise BundleError("bundle inputs exceed the remaining aggregate byte bound")
    destination = stage.joinpath(*relative.split("/"))
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise BundleError(f"cannot safely open input {source}: {error}") from error
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise BundleError(f"input changed before it could be copied: {source}")
        if opened.st_size > remaining:
            raise BundleError("bundle inputs exceed the remaining aggregate byte bound")
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARTIFACT_BYTES:
                    raise BundleError(f"input exceeds the per-artifact bound: {source}")
                if size > remaining:
                    raise BundleError("bundle inputs exceed the remaining aggregate byte bound")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise BundleError(f"short write while copying input: {source}")
                    view = view[written:]
            os.fsync(destination_fd)
            os.fchmod(destination_fd, mode)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        after = os.fstat(source_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(opened, field) != getattr(after, field) for field in stable_fields):
            raise BundleError(f"input changed while it was copied: {source}")
        if size != opened.st_size:
            raise BundleError(f"input size changed while it was copied: {source}")
    finally:
        os.close(source_fd)
    return _Copied(relative, digest.hexdigest(), size, f"{mode:04o}")


def _kill_probe(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _probe_capabilities(native: Path) -> dict[str, Any]:
    try:
        native_fd = os.open(native, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise BundleError(f"cannot safely open copied native artifact: {error}") from error
    try:
        before = os.fstat(native_fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o755:
            raise BundleError("copied native artifact is not a regular executable mode 0755 file")
        executable = f"/proc/self/fd/{native_fd}"
        try:
            process = subprocess.Popen(
                [executable, "capabilities", "--json"],
                executable=executable,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=(native_fd,),
            )
        except OSError as error:
            raise BundleError(f"cannot execute native capabilities probe: {error}") from error
    except Exception:
        os.close(native_fd)
        raise
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_probe(process)
                raise BundleError("native capabilities probe timed out")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = selector.select(0)
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output = outputs[key.data]
                output.extend(chunk)
                if len(output) > MAX_CAPABILITIES_BYTES:
                    _kill_probe(process)
                    raise BundleError(f"native capabilities probe {key.data} exceeded its bound")
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            _kill_probe(process)
            raise BundleError("native capabilities probe timed out") from error
    finally:
        selector.close()
        if process.poll() is None:
            _kill_probe(process)
            process.wait()
        process.stdout.close()
        process.stderr.close()
        after = os.fstat(native_fd)
        os.close(native_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise BundleError("copied native artifact changed during capabilities probe")
    if return_code != 0:
        raise BundleError(f"native capabilities probe exited {return_code}")
    if outputs["stderr"]:
        raise BundleError("native capabilities probe wrote unexpected stderr")
    document = _validate_capabilities(
        _load_json(bytes(outputs["stdout"]), label="native capabilities output"),
        label="native capabilities output",
    )
    return document


def _safe_label(value: str, *, label: str) -> str:
    result = _string(value, label=label, maximum=128)
    if not result[0].isalnum() or not result[-1].isalnum():
        raise BundleError(f"{label} must begin and end with an ASCII letter or digit")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"
    if any(character not in allowed for character in result) or ".." in result:
        raise BundleError(f"{label} contains an invalid character or component")
    return result


def _parse_host_path(value: str, *, label: str) -> tuple[str, Path]:
    host, separator, raw_path = value.partition("=")
    if not separator or not raw_path:
        raise BundleError(f"{label} must use HOST_CLASS=PATH")
    return _host_class(host, label=f"{label} host class"), Path(raw_path)


def _write_metadata(stage: Path, relative: str, content: bytes) -> _Copied:
    destination = stage.joinpath(*relative.split("/"))
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BundleError(f"short write while creating {relative}")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _Copied(relative, hashlib.sha256(content).hexdigest(), len(content), "0644")


def _fsync_tree(stage: Path) -> None:
    directories = [path for path in stage.rglob("*") if path.is_dir()]
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    descriptor = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _make_stage(parent_fd: int) -> tuple[str, Path]:
    for _ in range(128):
        name = f".outctl-w8-tmp-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as error:
            raise BundleError(f"cannot create pinned staging directory: {error}") from error
        return name, Path(f"/proc/self/fd/{parent_fd}/{name}")
    raise BundleError("cannot allocate a unique pinned staging directory")


def _require_pinned_parent_path(parent: Path, parent_fd: int) -> None:
    try:
        visible = parent.lstat()
    except OSError as error:
        raise BundleError("destination parent disappeared during assembly") from error
    pinned = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(visible.st_mode)
        or stat.S_ISLNK(visible.st_mode)
        or (visible.st_dev, visible.st_ino) != (pinned.st_dev, pinned.st_ino)
    ):
        raise BundleError("destination parent changed during assembly")


def _publish_noreplace(parent_fd: int, stage_name: str, destination_name: str) -> None:
    """Atomically publish with Linux renameat2 RENAME_NOREPLACE."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise BundleError("atomic no-replace publication requires Linux renameat2")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(stage_name),
        parent_fd,
        os.fsencode(destination_name),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise BundleError("destination appeared before atomic publication")
        raise BundleError(f"atomic no-replace publication failed: {os.strerror(error_number)}")


def build_bundle(
    *,
    release: str,
    version: str,
    repository_commit: str,
    wheel: Path,
    native_arguments: list[str],
    dependency_arguments: list[str],
    destination: Path,
) -> dict[str, Any]:
    release = _safe_label(release, label="release")
    version = _safe_label(version, label="version")
    if re.fullmatch(r"[a-f0-9]{40}", repository_commit) is None:
        raise BundleError("repository commit must be a full lowercase Git SHA")
    if not native_arguments or len(native_arguments) > MAX_NATIVE_VARIANTS:
        raise BundleError(f"provide between 1 and {MAX_NATIVE_VARIANTS} --native values")
    natives: dict[str, Path] = {}
    for value in native_arguments:
        host, path = _parse_host_path(value, label="--native")
        if host in natives:
            raise BundleError(f"duplicate native host class: {host!r}")
        natives[host] = path
    dependencies: dict[str, list[Path]] = {host: [] for host in natives}
    for value in dependency_arguments:
        host, path = _parse_host_path(value, label="--python-dependency")
        if host not in natives:
            raise BundleError(f"Python dependency names unknown native host class: {host!r}")
        dependencies[host].append(path)
        if len(dependencies[host]) > MAX_DEPENDENCIES_PER_HOST:
            raise BundleError(f"too many Python dependencies for host class {host!r}")
    missing_dependencies = sorted(host for host, values in dependencies.items() if not values)
    if missing_dependencies:
        raise BundleError(f"native host classes lack Python dependencies: {missing_dependencies!r}")

    # Reject aggregate exhaustion before staging a single byte. The copy loop
    # still rechecks each opened file for identity/size stability.
    declared_total = 0
    for source in (
        wheel,
        *natives.values(),
        *(path for values in dependencies.values() for path in values),
    ):
        declared_total += _validate_source(source).st_size
        if declared_total > MAX_BUNDLE_INPUT_BYTES:
            raise BundleError("bundle inputs exceed the aggregate byte bound")

    parent = destination.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise BundleError(f"destination parent does not exist: {parent}") from error
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
        raise BundleError("destination parent must be a real directory")
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise BundleError(f"cannot safely open destination parent: {error}") from error
    stage: Path | None = None
    try:
        opened_parent = os.fstat(parent_fd)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_metadata.st_dev,
            parent_metadata.st_ino,
        ):
            raise BundleError("destination parent changed before it could be pinned")
        destination_name = destination.name
        if destination_name in {"", ".", ".."}:
            raise BundleError("destination must name a direct child of its parent")
        try:
            os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise BundleError(f"cannot inspect destination: {error}") from error
        else:
            raise BundleError("refusing to replace any pre-existing destination")

        stage_name, stage = _make_stage(parent_fd)
        total_input_bytes = 0
        wheel_filename = _wheel_filename(wheel.name, label="main wheel filename")
        main_copy = _copy_input(
            wheel,
            stage,
            f"artifacts/python/{wheel_filename}",
            mode=0o644,
            remaining=MAX_BUNDLE_INPUT_BYTES - total_input_bytes,
        )
        total_input_bytes = _account_bundle_bytes(total_input_bytes, main_copy)
        main_metadata = _wheel_metadata(stage / main_copy.path, expected_main=True)

        native_entries: list[dict[str, object]] = []
        expected_engine: tuple[str, str] | None = None
        expected_profile: bytes | None = None
        for host in sorted(natives):
            native_copy = _copy_input(
                natives[host],
                stage,
                f"artifacts/outctl-native.{host}",
                mode=0o755,
                remaining=MAX_BUNDLE_INPUT_BYTES - total_input_bytes,
            )
            total_input_bytes = _account_bundle_bytes(total_input_bytes, native_copy)
            capability_document = _probe_capabilities(stage / native_copy.path)
            engine = capability_document["engine"]
            engine_identity = (engine["id"], engine["version"])
            profile = canonical_json(capability_profile(capability_document))
            if expected_engine is None:
                expected_engine = engine_identity
                expected_profile = profile
            elif engine_identity != expected_engine:
                raise BundleError("native variants report mismatched engine identity or version")
            elif profile != expected_profile:
                raise BundleError("native variants report mismatched capabilities")
            capability_bytes = canonical_json(capability_document)
            capability_copy = _write_metadata(
                stage, f"metadata/capabilities.{host}.json", capability_bytes
            )

            dependency_entries: list[dict[str, object]] = []
            project_names: set[str] = set()
            filenames: set[str] = set()
            dependency_requirements: dict[str, frozenset[str]] = {}
            for dependency in dependencies[host]:
                dependency_filename = _wheel_filename(
                    dependency.name, label=f"dependency filename for {host}"
                )
                folded_filename = dependency_filename.casefold()
                if folded_filename in filenames:
                    raise BundleError(
                        f"duplicate dependency wheel filename for {host!r}: {dependency_filename!r}"
                    )
                filenames.add(folded_filename)
                relative = f"artifacts/python-dependencies/{host}/{dependency_filename}"
                dependency_copy = _copy_input(
                    dependency,
                    stage,
                    relative,
                    mode=0o644,
                    remaining=MAX_BUNDLE_INPUT_BYTES - total_input_bytes,
                )
                total_input_bytes = _account_bundle_bytes(total_input_bytes, dependency_copy)
                metadata = _wheel_metadata(stage / dependency_copy.path)
                if metadata.name == "outctl" or metadata.name in project_names:
                    raise BundleError(
                        f"duplicate Python project name for {host!r}: {metadata.name!r}"
                    )
                project_names.add(metadata.name)
                dependency_requirements[metadata.name] = metadata.requirements
                dependency_entries.append(
                    {
                        "name": metadata.name,
                        "version": metadata.version,
                        "filename": dependency_filename,
                        **dependency_copy.pin(),
                    }
                )
            required_projects = set(main_metadata.requirements)
            for requirements in dependency_requirements.values():
                required_projects.update(requirements)
            required_projects.discard("outctl")
            missing_projects = sorted(required_projects - project_names)
            if missing_projects:
                raise BundleError(
                    f"Python dependency set for {host!r} is incomplete: {missing_projects!r}"
                )
            dependency_entries.sort(key=lambda item: (str(item["name"]), str(item["filename"])))
            native_entries.append(
                {
                    "name": f"outctl-native:{host}",
                    "host_class": host,
                    **native_copy.pin(),
                    "engine": {
                        "id": engine["id"],
                        "version": engine["version"],
                        "platform": engine["platform"],
                    },
                    "capabilities": capability_copy.pin(),
                    "python_dependencies": dependency_entries,
                }
            )
        assert expected_profile is not None
        manifest: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "release": {
                "id": release,
                "version": version,
                "repository_commit": repository_commit,
                "capability_profile_sha256": hashlib.sha256(expected_profile).hexdigest(),
            },
            "python": {
                "name": main_metadata.name,
                "version": main_metadata.version,
                "filename": wheel_filename,
                **main_copy.pin(),
            },
            "native": native_entries,
        }
        _write_metadata(stage, "manifest.json", canonical_json(manifest) + b"\n")
        check_bundle(stage)
        os.chmod(stage, 0o755)
        _fsync_tree(stage)
        _require_pinned_parent_path(parent, parent_fd)
        _publish_noreplace(parent_fd, stage_name, destination_name)
        os.fsync(parent_fd)
        return manifest
    except Exception:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)
        raise
    finally:
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, help="repository release identifier")
    parser.add_argument(
        "--version", required=True, help="bundle release label (not an artifact-version assertion)"
    )
    parser.add_argument(
        "--repository-commit",
        required=True,
        help="exact 40-character source Git commit shared by the built artifacts",
    )
    parser.add_argument("--wheel", required=True, type=Path, help="built outctl Python wheel")
    parser.add_argument(
        "--native",
        required=True,
        action="append",
        metavar="HOST_CLASS=PATH",
        help="native artifact and its deployment host class; repeat for each class",
    )
    parser.add_argument(
        "--python-dependency",
        required=True,
        action="append",
        metavar="HOST_CLASS=PATH",
        help="host-specific dependency wheel; repeat for every complete wheelhouse",
    )
    parser.add_argument("--destination", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        manifest = build_bundle(
            release=arguments.release,
            version=arguments.version,
            repository_commit=arguments.repository_commit,
            wheel=arguments.wheel,
            native_arguments=arguments.native,
            dependency_arguments=arguments.python_dependency,
            destination=arguments.destination,
        )
    except BundleError as error:
        parser.error(str(error))
    print(canonical_json(bundle_check_report(manifest)).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
