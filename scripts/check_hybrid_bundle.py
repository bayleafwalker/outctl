"""Read-only verification for a local Outctl hybrid release bundle.

The checker deliberately has no discovery or execution fallback.  Every path is
derived from strict manifest fields, opened beneath a pinned bundle directory,
and checked against the recorded digest, size, and mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

SCHEMA_VERSION: Final = "outctl.hybrid-release/v1"
MANIFEST_NAME: Final = "manifest.json"
MAX_MANIFEST_BYTES: Final = 1_048_576
MAX_CAPABILITIES_BYTES: Final = 1_048_576
MAX_ARTIFACT_BYTES: Final = 512 * 1024 * 1024
MAX_BUNDLE_INPUT_BYTES: Final = 4 * 1024 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")


class BundleError(ValueError):
    """The bundle is malformed or no longer matches its pins."""


@dataclass(frozen=True)
class _Pin:
    path: str
    sha256: str
    size: int
    mode: str


def canonical_json(value: object) -> bytes:
    """Return the repository's deterministic JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def capability_profile(document: dict[str, Any]) -> dict[str, Any]:
    """Return cross-host capabilities with only the platform fact removed."""

    profile = json.loads(canonical_json(document))
    del profile["engine"]["platform"]
    return profile


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _load_json(raw: bytes, *, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleError(f"{label} is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                BundleError(f"{label} contains non-finite number {value}")
            ),
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise BundleError(f"{label} is not valid JSON: {error}") from error


def _exact_keys(value: Any, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise BundleError(
            f"{label} keys differ: missing={sorted(expected - actual)!r}, "
            f"unexpected={sorted(actual - expected)!r}"
        )
    return value


def _string(value: Any, *, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise BundleError(f"{label} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise BundleError(f"{label} contains a control character")
    return value


def _digest(value: Any, *, label: str) -> str:
    digest = _string(value, label=label, maximum=64)
    if len(digest) != 64 or any(character not in _HEX for character in digest):
        raise BundleError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _size(value: Any, *, label: str, maximum: int = MAX_ARTIFACT_BYTES) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise BundleError(f"{label} must be an integer in 0..{maximum}")
    return value


def _mode(value: Any, *, label: str, expected: str) -> str:
    if value != expected:
        raise BundleError(f"{label} must be {expected!r}")
    return expected


def _safe_relative(value: Any, *, label: str, expected: str) -> str:
    path = _string(value, label=label, maximum=512)
    parsed = PurePosixPath(path)
    if (
        path != parsed.as_posix()
        or parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise BundleError(f"{label} is not a normalized bundle-relative path")
    if path != expected:
        raise BundleError(f"{label} must be the fixed path {expected!r}")
    return path


def _pin(value: Any, *, label: str, expected_path: str, expected_mode: str) -> _Pin:
    item = _exact_keys(value, {"path", "sha256", "size", "mode"}, label=label)
    return _Pin(
        path=_safe_relative(item["path"], label=f"{label}.path", expected=expected_path),
        sha256=_digest(item["sha256"], label=f"{label}.sha256"),
        size=_size(item["size"], label=f"{label}.size"),
        mode=_mode(item["mode"], label=f"{label}.mode", expected=expected_mode),
    )


def _wheel_filename(value: Any, *, label: str) -> str:
    name = _string(value, label=label, maximum=255)
    if name != PurePosixPath(name).name or not name.endswith(".whl"):
        raise BundleError(f"{label} must be a traversal-free wheel basename")
    if any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        for character in name
    ):
        raise BundleError(f"{label} contains an unsafe character")
    if name.startswith((".", "-")):
        raise BundleError(f"{label} has an unsafe prefix")
    components = name.removesuffix(".whl").split("-")
    if len(components) not in {5, 6}:
        raise BundleError(f"{label} is not a PEP 427 wheel filename")
    distribution, version, *middle = components
    if any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        for character in distribution
    ):
        raise BundleError(f"{label} has an invalid normalized distribution component")
    if not version:
        raise BundleError(f"{label} has an empty version component")
    if len(middle) == 4 and (not middle[0] or not middle[0][0].isdigit()):
        raise BundleError(f"{label} has an invalid build-tag component")
    tag_components = middle[-3:]
    if any(
        not component
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_."
            for character in component
        )
        for component in tag_components
    ):
        raise BundleError(f"{label} has an invalid compatibility-tag component")
    return name


def _host_class(value: Any, *, label: str) -> str:
    host = _string(value, label=label, maximum=64)
    if not host[0].isalnum() or not host[-1].isalnum():
        raise BundleError(f"{label} must begin and end with an ASCII lowercase letter or digit")
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in host):
        raise BundleError(f"{label} contains an invalid character")
    if any(marker in host for marker in ("..", "--", "__", ".-", "-.", "._", "_.")):
        raise BundleError(f"{label} contains an empty or ambiguous component")
    return host


def _validate_capabilities(value: Any, *, label: str) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {"schema_version", "engine", "contract_versions", "features", "limits"},
        label=label,
    )
    if document["schema_version"] != "vuoro.outctl.engine-capabilities/v2":
        raise BundleError(f"{label}.schema_version is unsupported")
    engine = _exact_keys(document["engine"], {"id", "version", "platform"}, label=f"{label}.engine")
    for key in ("id", "version", "platform"):
        _string(engine[key], label=f"{label}.engine.{key}", maximum=128)

    contracts = _exact_keys(
        document["contract_versions"],
        {"run_request", "policy_snapshot", "run_result", "capture_manifest"},
        label=f"{label}.contract_versions",
    )
    for key, versions in contracts.items():
        if not isinstance(versions, list) or not versions:
            raise BundleError(f"{label}.contract_versions.{key} must be a non-empty array")
        if len(versions) > 16 or len(set(map(str, versions))) != len(versions):
            raise BundleError(f"{label}.contract_versions.{key} has duplicate or excess entries")
        for index, version in enumerate(versions):
            _string(version, label=f"{label}.contract_versions.{key}[{index}]", maximum=32)

    features = _exact_keys(
        document["features"],
        {
            "direct_argv",
            "explicit_shell",
            "stdin",
            "retrieval",
            "one_version_back_read",
            "pty",
            "live_output",
            "parent_shell_state",
        },
        label=f"{label}.features",
    )
    if any(not isinstance(setting, bool) for setting in features.values()):
        raise BundleError(f"{label}.features values must be booleans")
    if features["direct_argv"] is not True or features["one_version_back_read"] is not True:
        raise BundleError(f"{label}.features lacks a required v2 invariant")

    limits = _exact_keys(
        document["limits"],
        {"max_argv_items", "max_capture_bytes", "max_projection_bytes"},
        label=f"{label}.limits",
    )
    for key, limit in limits.items():
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise BundleError(f"{label}.limits.{key} must be a positive integer")
    return document


def _read_pinned_file(root_fd: int, pin: _Pin, *, maximum: int | None = None) -> bytes:
    parts = PurePosixPath(pin.path).parts
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current_fd)
        try:
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise BundleError(f"bundle member {pin.path!r} is not a regular file")
            observed_mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            if observed_mode != pin.mode:
                raise BundleError(
                    f"bundle member {pin.path!r} mode drift: "
                    f"expected {pin.mode}, got {observed_mode}"
                )
            if metadata.st_size != pin.size:
                raise BundleError(
                    f"bundle member {pin.path!r} size drift: "
                    f"expected {pin.size}, got {metadata.st_size}"
                )
            if maximum is not None and metadata.st_size > maximum:
                raise BundleError(f"bundle member {pin.path!r} exceeds its verification bound")
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
                if maximum is not None:
                    if total > maximum:
                        raise BundleError(
                            f"bundle member {pin.path!r} exceeds its verification bound"
                        )
                    chunks.append(chunk)
            if total != pin.size or digest.hexdigest() != pin.sha256:
                raise BundleError(f"bundle member {pin.path!r} digest or size drift")
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    except OSError as error:
        raise BundleError(f"cannot safely read bundle member {pin.path!r}: {error}") from error
    finally:
        os.close(current_fd)


def _read_manifest(root_fd: int) -> tuple[dict[str, Any], bytes]:
    try:
        manifest_fd = os.open(MANIFEST_NAME, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            metadata = os.fstat(manifest_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise BundleError("manifest.json is not a regular file")
            if stat.S_IMODE(metadata.st_mode) != 0o644:
                raise BundleError("manifest.json mode must be 0644")
            if metadata.st_size > MAX_MANIFEST_BYTES:
                raise BundleError("manifest.json exceeds its verification bound")
            raw = b""
            while len(raw) <= MAX_MANIFEST_BYTES:
                chunk = os.read(manifest_fd, min(65_536, MAX_MANIFEST_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(manifest_fd)
    except OSError as error:
        raise BundleError(f"cannot safely read manifest.json: {error}") from error
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BundleError("manifest.json exceeds its verification bound")
    value = _load_json(raw, label="manifest.json")
    manifest = _exact_keys(
        value, {"schema_version", "release", "python", "native"}, label="manifest"
    )
    if raw != canonical_json(manifest) + b"\n":
        raise BundleError("manifest.json is not canonical JSON with one trailing newline")
    return manifest, raw


def _expected_directories(files: set[str]) -> set[str]:
    directories = {""}
    for filename in files:
        parent = PurePosixPath(filename).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _verify_exact_members(root_fd: int, expected_files: set[str]) -> None:
    """Descriptor-relatively reject every unmanifested or unsafe member."""

    expected_directories = _expected_directories(expected_files)
    observed_files: set[str] = set()
    observed_directories = {""}
    pending: list[tuple[str, int]] = [("", os.dup(root_fd))]
    try:
        while pending:
            relative_directory, directory_fd = pending.pop()
            try:
                try:
                    entries = list(os.scandir(directory_fd))
                except OSError as error:
                    raise BundleError(
                        f"cannot enumerate bundle directory {relative_directory or '.'!r}: {error}"
                    ) from error
                for entry in entries:
                    if entry.name in {".", ".."} or "/" in entry.name or "\x00" in entry.name:
                        raise BundleError("bundle contains an invalid directory entry")
                    relative = (
                        f"{relative_directory}/{entry.name}" if relative_directory else entry.name
                    )
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        raise BundleError(
                            f"cannot inspect bundle member {relative!r}: {error}"
                        ) from error
                    if stat.S_ISLNK(metadata.st_mode):
                        raise BundleError(f"bundle contains symlink member {relative!r}")
                    if stat.S_ISDIR(metadata.st_mode):
                        if metadata.st_mode & 0o022:
                            raise BundleError(
                                f"bundle directory {relative!r} is group/world writable"
                            )
                        if relative not in expected_directories:
                            raise BundleError(
                                f"bundle contains unmanifested directory {relative!r}"
                            )
                        try:
                            child_fd = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory_fd,
                            )
                        except OSError as error:
                            raise BundleError(
                                f"cannot safely open bundle directory {relative!r}: {error}"
                            ) from error
                        opened_metadata = os.fstat(child_fd)
                        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
                            metadata.st_dev,
                            metadata.st_ino,
                        ):
                            os.close(child_fd)
                            raise BundleError(
                                f"bundle directory {relative!r} changed during enumeration"
                            )
                        if opened_metadata.st_mode & 0o022:
                            os.close(child_fd)
                            raise BundleError(
                                f"bundle directory {relative!r} is group/world writable"
                            )
                        observed_directories.add(relative)
                        pending.append((relative, child_fd))
                    elif stat.S_ISREG(metadata.st_mode):
                        if relative not in expected_files:
                            raise BundleError(f"bundle contains unmanifested file {relative!r}")
                        observed_files.add(relative)
                    else:
                        raise BundleError(f"bundle contains special member {relative!r}")
            finally:
                os.close(directory_fd)
    finally:
        for _, pending_fd in pending:
            os.close(pending_fd)
    if observed_files != expected_files:
        raise BundleError(
            f"bundle members are missing: {sorted(expected_files - observed_files)!r}"
        )
    if observed_directories != expected_directories:
        raise BundleError(
            f"bundle directories are missing: "
            f"{sorted(expected_directories - observed_directories)!r}"
        )


def bundle_check_report(manifest: dict[str, Any]) -> dict[str, object]:
    """Return a stable metadata-only receipt with a ``sha256:<hex>`` pin."""

    return {
        "schema_version": "outctl.hybrid-bundle-check/v1",
        "release_id": manifest["release"]["id"],
        "release_version": manifest["release"]["version"],
        "repository_commit": manifest["release"]["repository_commit"],
        "manifest_sha256": (
            f"sha256:{hashlib.sha256(canonical_json(manifest) + b'\n').hexdigest()}"
        ),
        "host_classes": sorted(native["host_class"] for native in manifest["native"]),
    }


def check_bundle(bundle: Path) -> dict[str, Any]:
    """Verify a bundle without executing its artifacts and return its manifest."""

    try:
        root_metadata = bundle.lstat()
    except OSError as error:
        raise BundleError(f"cannot inspect bundle root: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise BundleError("bundle root must be a real directory, not a symlink")
    if root_metadata.st_mode & 0o022:
        raise BundleError("bundle root must not be group/world writable")
    try:
        root_fd = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise BundleError(f"cannot safely open bundle root: {error}") from error
    try:
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (
            root_metadata.st_dev,
            root_metadata.st_ino,
        ):
            raise BundleError("bundle root changed before it could be pinned")
        if opened_root.st_mode & 0o022:
            raise BundleError("bundle root must not be group/world writable")
        manifest, _ = _read_manifest(root_fd)
        expected_files = {MANIFEST_NAME}
        if manifest["schema_version"] != SCHEMA_VERSION:
            raise BundleError("manifest.schema_version is unsupported")

        release = _exact_keys(
            manifest["release"],
            {"id", "version", "repository_commit", "capability_profile_sha256"},
            label="release",
        )
        _string(release["id"], label="release.id", maximum=128)
        _string(release["version"], label="release.version", maximum=128)
        repository_commit = _string(
            release["repository_commit"], label="release.repository_commit", maximum=40
        )
        if len(repository_commit) != 40 or any(
            character not in _HEX for character in repository_commit
        ):
            raise BundleError("release.repository_commit must be a full lowercase Git SHA")
        profile_digest = _digest(
            release["capability_profile_sha256"], label="release.capability_profile_sha256"
        )

        python = _exact_keys(
            manifest["python"],
            {"name", "version", "filename", "path", "sha256", "size", "mode"},
            label="python",
        )
        if python["name"] != "outctl":
            raise BundleError("python.name must be 'outctl'")
        _string(python["version"], label="python.version", maximum=128)
        filename = _wheel_filename(python["filename"], label="python.filename")
        main_pin = _pin(
            {key: python[key] for key in ("path", "sha256", "size", "mode")},
            label="python",
            expected_path=f"artifacts/python/{filename}",
            expected_mode="0644",
        )
        artifact_total = main_pin.size
        _read_pinned_file(root_fd, main_pin)
        expected_files.add(main_pin.path)

        natives = manifest["native"]
        if not isinstance(natives, list) or not natives or len(natives) > 64:
            raise BundleError("native must contain between 1 and 64 entries")
        hosts: set[str] = set()
        names: set[str] = set()
        expected_native_order: list[str] = []
        expected_engine_id: str | None = None
        expected_engine_version: str | None = None
        expected_profile: bytes | None = None
        for index, raw_native in enumerate(natives):
            label = f"native[{index}]"
            native = _exact_keys(
                raw_native,
                {
                    "name",
                    "host_class",
                    "path",
                    "sha256",
                    "size",
                    "mode",
                    "engine",
                    "capabilities",
                    "python_dependencies",
                },
                label=label,
            )
            host = _host_class(native["host_class"], label=f"{label}.host_class")
            expected_name = f"outctl-native:{host}"
            if native["name"] != expected_name:
                raise BundleError(f"{label}.name must be {expected_name!r}")
            if host in hosts or expected_name in names:
                raise BundleError(f"duplicate native host class or name: {host!r}")
            hosts.add(host)
            names.add(expected_name)
            expected_native_order.append(host)
            native_pin = _pin(
                {key: native[key] for key in ("path", "sha256", "size", "mode")},
                label=label,
                expected_path=f"artifacts/outctl-native.{host}",
                expected_mode="0755",
            )
            artifact_total += native_pin.size
            if artifact_total > MAX_BUNDLE_INPUT_BYTES:
                raise BundleError("bundle artifacts exceed the aggregate byte bound")
            _read_pinned_file(root_fd, native_pin)
            expected_files.add(native_pin.path)

            engine = _exact_keys(
                native["engine"], {"id", "version", "platform"}, label=f"{label}.engine"
            )
            engine_id = _string(engine["id"], label=f"{label}.engine.id", maximum=128)
            engine_version = _string(
                engine["version"], label=f"{label}.engine.version", maximum=128
            )
            _string(engine["platform"], label=f"{label}.engine.platform", maximum=128)
            if expected_engine_id is None:
                expected_engine_id = engine_id
                expected_engine_version = engine_version
            elif engine_id != expected_engine_id or engine_version != expected_engine_version:
                raise BundleError("native variants report mismatched engine identity or version")

            dependencies = native["python_dependencies"]
            if not isinstance(dependencies, list) or not dependencies or len(dependencies) > 256:
                raise BundleError(f"{label}.python_dependencies must contain 1 to 256 entries")
            dependency_names: set[str] = set()
            dependency_files: set[str] = set()
            expected_dependency_order: list[tuple[str, str]] = []
            for dependency_index, raw_dependency in enumerate(dependencies):
                dependency_label = f"{label}.python_dependencies[{dependency_index}]"
                dependency = _exact_keys(
                    raw_dependency,
                    {"name", "version", "filename", "path", "sha256", "size", "mode"},
                    label=dependency_label,
                )
                dependency_name = _string(
                    dependency["name"], label=f"{dependency_label}.name", maximum=128
                )
                if dependency_name != dependency_name.lower() or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                    for character in dependency_name
                ):
                    raise BundleError(f"{dependency_label}.name is not a canonical project name")
                if dependency_name == "outctl" or dependency_name in dependency_names:
                    raise BundleError(
                        f"duplicate Python project name for {host!r}: {dependency_name!r}"
                    )
                dependency_names.add(dependency_name)
                _string(dependency["version"], label=f"{dependency_label}.version", maximum=128)
                dependency_filename = _wheel_filename(
                    dependency["filename"], label=f"{dependency_label}.filename"
                )
                folded_filename = dependency_filename.casefold()
                if folded_filename in dependency_files:
                    raise BundleError(
                        f"duplicate dependency wheel filename for {host!r}: {dependency_filename!r}"
                    )
                dependency_files.add(folded_filename)
                dependency_pin = _pin(
                    {key: dependency[key] for key in ("path", "sha256", "size", "mode")},
                    label=dependency_label,
                    expected_path=(f"artifacts/python-dependencies/{host}/{dependency_filename}"),
                    expected_mode="0644",
                )
                artifact_total += dependency_pin.size
                if artifact_total > MAX_BUNDLE_INPUT_BYTES:
                    raise BundleError("bundle artifacts exceed the aggregate byte bound")
                _read_pinned_file(root_fd, dependency_pin)
                expected_files.add(dependency_pin.path)
                expected_dependency_order.append((dependency_name, dependency_filename))
            if expected_dependency_order != sorted(expected_dependency_order):
                raise BundleError(
                    f"{label}.python_dependencies is not in canonical project/filename order"
                )

            capabilities_value = _exact_keys(
                native["capabilities"],
                {"path", "sha256", "size", "mode"},
                label=f"{label}.capabilities",
            )
            capabilities_pin = _pin(
                capabilities_value,
                label=f"{label}.capabilities",
                expected_path=f"metadata/capabilities.{host}.json",
                expected_mode="0644",
            )
            capabilities_raw = _read_pinned_file(
                root_fd, capabilities_pin, maximum=MAX_CAPABILITIES_BYTES
            )
            expected_files.add(capabilities_pin.path)
            capabilities = _validate_capabilities(
                _load_json(capabilities_raw, label=capabilities_pin.path),
                label=capabilities_pin.path,
            )
            if capabilities_raw != canonical_json(capabilities):
                raise BundleError(f"{capabilities_pin.path} is not canonical JSON")
            if capabilities["engine"] != engine:
                raise BundleError(f"{label}.engine does not match its capability document")
            profile = canonical_json(capability_profile(capabilities))
            if expected_profile is None:
                expected_profile = profile
            elif profile != expected_profile:
                raise BundleError("native variants report mismatched capabilities")
        if expected_native_order != sorted(expected_native_order):
            raise BundleError("native entries are not in canonical host-class order")
        if (
            expected_profile is None
            or hashlib.sha256(expected_profile).hexdigest() != profile_digest
        ):
            raise BundleError(
                "release.capability_profile_sha256 does not match native capabilities"
            )
        _verify_exact_members(root_fd, expected_files)
        return manifest
    finally:
        os.close(root_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="local hybrid bundle directory")
    parser.add_argument(
        "--manifest-sha256",
        help=("trusted exact manifest digest as lowercase 64-hex or sha256:<lowercase-64-hex>"),
    )
    arguments = parser.parse_args()
    try:
        manifest = check_bundle(arguments.bundle)
        report = bundle_check_report(manifest)
        if arguments.manifest_sha256 is not None:
            supplied = arguments.manifest_sha256
            expected_hex = supplied.removeprefix("sha256:")
            expected = f"sha256:{_digest(expected_hex, label='--manifest-sha256')}"
            if report["manifest_sha256"] != expected:
                raise BundleError("manifest digest does not match --manifest-sha256")
    except BundleError as error:
        parser.error(str(error))
    print(canonical_json(report).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
