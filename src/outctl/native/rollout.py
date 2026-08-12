"""Fail-closed local selection for the W8 staged native rollout.

This module does not install artifacts, enable a deployment, or mutate rollout
evidence.  It consumes an already verified release digest plus metadata-only
gate evidence supplied by the embedding runner.  The ordinary Python path
remains the fallback unless an explicit canary or default-native decision is
both eligible and capability-compatible.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from outctl.control import (
    CapabilityRequirement,
    EngineCapabilities,
    negotiate_capabilities,
)
from outctl.native.selector import (
    EngineChoice,
    EngineSelection,
    NativeEngineUnavailable,
)

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_TOKEN_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_MAX_CAPABILITY_BYTES: Final = 1024 * 1024


class RolloutEvidenceError(ValueError):
    """Raised when staged-rollout evidence is malformed or contradictory."""


class RolloutTrack(StrEnum):
    PYTHON = "python-reference"
    SHADOW = "rust-shadow"
    CANARY = "rust-canary"
    NATIVE_DEFAULT = "rust-default"


class RolloutMode(StrEnum):
    """Deployment-facing modes without importing the legacy adapter engine."""

    BYPASS = "bypass"
    SHADOW = "shadow"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class HostClass:
    """The install-facing host class, independent of a workflow identity."""

    operating_system: str
    architecture: str
    libc: str
    python_abi: str

    def __post_init__(self) -> None:
        for label, value in (
            ("operating_system", self.operating_system),
            ("architecture", self.architecture),
            ("libc", self.libc),
            ("python_abi", self.python_abi),
        ):
            if _TOKEN_RE.fullmatch(value) is None:
                raise RolloutEvidenceError(f"invalid host-class {label}: {value!r}")

    @property
    def identifier(self) -> str:
        return "-".join((self.operating_system, self.architecture, self.libc, self.python_abi))

    @property
    def native_platform(self) -> str:
        return f"{self.operating_system}-{self.architecture}"

    @classmethod
    def current(cls) -> HostClass:
        system = platform.system().casefold()
        machine = platform.machine().casefold()
        architecture = {
            "amd64": "x86_64",
            "arm64": "aarch64",
        }.get(machine, machine)
        libc_name, _ = platform.libc_ver()
        libc = libc_name.casefold() or ("none" if system != "linux" else "unknown")
        python_abi = f"cp{sys.version_info.major}{sys.version_info.minor}"
        return cls(system, architecture, libc, python_abi)


@dataclass(frozen=True)
class WaveGate:
    wave: int
    commit: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.wave not in range(8):
            raise RolloutEvidenceError("prior wave must be in W0-W7")
        if re.fullmatch(r"[a-f0-9]{40}", self.commit) is None:
            raise RolloutEvidenceError(f"W{self.wave} commit must be a full Git SHA")
        _validate_evidence_ids(self.evidence_ids, label=f"W{self.wave}")


@dataclass(frozen=True)
class HostArtifactPin:
    host_class: str
    native_sha256: str
    capabilities_sha256: str

    def __post_init__(self) -> None:
        if _TOKEN_RE.fullmatch(self.host_class) is None:
            raise RolloutEvidenceError("invalid pinned host class")
        for label, value in (
            ("native artifact", self.native_sha256),
            ("native capabilities", self.capabilities_sha256),
        ):
            if _DIGEST_RE.fullmatch(value) is None:
                raise RolloutEvidenceError(f"{label} digest must be sha256:<hex>")


@dataclass(frozen=True)
class RolloutEvidence:
    """Metadata-only gates required before selecting a native artifact."""

    release_manifest_digest: str
    repository_commit: str
    host_artifacts: tuple[HostArtifactPin, ...]
    prior_waves: tuple[WaveGate, ...]
    clean_install_passed: bool
    host_conformance_passed: bool
    shadow_passed: bool
    rollback_passed: bool
    canary_passed: bool
    evidence_ids: tuple[str, ...]
    canary_basis_points: int = 0
    native_default_enabled: bool = False
    native_default_authorization: str | None = None

    def __post_init__(self) -> None:
        if _DIGEST_RE.fullmatch(self.release_manifest_digest) is None:
            raise RolloutEvidenceError("release manifest digest must be sha256:<hex>")
        if re.fullmatch(r"[a-f0-9]{40}", self.repository_commit) is None:
            raise RolloutEvidenceError("repository commit must be a full Git SHA")
        if not self.host_artifacts:
            raise RolloutEvidenceError("at least one pinned host artifact is required")
        if len(self.host_artifacts) > 32:
            raise RolloutEvidenceError("at most 32 pinned host artifacts are supported")
        host_classes = tuple(item.host_class for item in self.host_artifacts)
        if host_classes != tuple(sorted(host_classes)) or len(set(host_classes)) != len(
            host_classes
        ):
            raise RolloutEvidenceError("pinned host artifacts must be unique and sorted")
        waves = tuple(gate.wave for gate in self.prior_waves)
        if waves != tuple(range(8)):
            raise RolloutEvidenceError("prior wave evidence must contain W0-W7 exactly once")
        _validate_evidence_ids(self.evidence_ids, label="rollout")
        for label, value in (
            ("clean_install_passed", self.clean_install_passed),
            ("host_conformance_passed", self.host_conformance_passed),
            ("shadow_passed", self.shadow_passed),
            ("rollback_passed", self.rollback_passed),
            ("canary_passed", self.canary_passed),
            ("native_default_enabled", self.native_default_enabled),
        ):
            if type(value) is not bool:
                raise RolloutEvidenceError(f"{label} must be a boolean")
        if not 0 <= self.canary_basis_points <= 10_000:
            raise RolloutEvidenceError("canary basis points must be in 0..10000")
        if self.native_default_enabled and not self.native_default_authorization:
            raise RolloutEvidenceError(
                "native default requires an external authorization reference"
            )
        if not self.native_default_enabled and self.native_default_authorization is not None:
            raise RolloutEvidenceError("disabled native default cannot carry authorization")
        if (
            self.native_default_authorization is not None
            and len(self.native_default_authorization) > 256
        ):
            raise RolloutEvidenceError("native default authorization is too long")

    @property
    def pre_shadow_passed(self) -> bool:
        return all(
            (
                self.clean_install_passed,
                self.host_conformance_passed,
                self.rollback_passed,
            )
        )

    @property
    def pre_canary_passed(self) -> bool:
        return self.pre_shadow_passed and self.shadow_passed

    @property
    def default_passed(self) -> bool:
        return self.pre_canary_passed and self.canary_passed

    @property
    def host_classes(self) -> frozenset[str]:
        return frozenset(item.host_class for item in self.host_artifacts)

    def artifact_for(self, host_class: str) -> HostArtifactPin | None:
        return next(
            (item for item in self.host_artifacts if item.host_class == host_class),
            None,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> RolloutEvidence:
        _exact_keys(
            value,
            {
                "schema_version",
                "release_manifest_digest",
                "repository_commit",
                "host_artifacts",
                "prior_waves",
                "gates",
                "rollout",
                "evidence_ids",
            },
            label="W8 adoption evidence",
        )
        if value.get("schema_version") != "vuoro.outctl.w8-adoption-evidence/v1":
            raise RolloutEvidenceError("unsupported W8 adoption evidence schema")
        try:
            wave_values = value["prior_waves"]
            gates = value["gates"]
            rollout = value["rollout"]
            if not isinstance(wave_values, list):
                raise TypeError
            if not isinstance(gates, Mapping) or not isinstance(rollout, Mapping):
                raise TypeError
            _exact_keys(
                gates,
                {
                    "clean_install_passed",
                    "host_conformance_passed",
                    "shadow_passed",
                    "rollback_passed",
                    "canary_passed",
                },
                label="gates",
            )
            _exact_keys(
                rollout,
                {
                    "canary_basis_points",
                    "native_default_enabled",
                    "native_default_authorization",
                },
                label="rollout",
            )
            prior_waves = tuple(_wave_gate(item) for item in wave_values)
            host_values = value["host_artifacts"]
            evidence_values = value["evidence_ids"]
            if not isinstance(host_values, list):
                raise TypeError
            if not isinstance(evidence_values, list) or not all(
                isinstance(item, str) for item in evidence_values
            ):
                raise TypeError
            return cls(
                release_manifest_digest=_string(value, "release_manifest_digest"),
                repository_commit=_string(value, "repository_commit"),
                host_artifacts=tuple(_host_artifact(item) for item in host_values),
                prior_waves=prior_waves,
                clean_install_passed=_strict_bool(gates, "clean_install_passed"),
                host_conformance_passed=_strict_bool(gates, "host_conformance_passed"),
                shadow_passed=_strict_bool(gates, "shadow_passed"),
                rollback_passed=_strict_bool(gates, "rollback_passed"),
                canary_passed=_strict_bool(gates, "canary_passed"),
                evidence_ids=tuple(evidence_values),
                canary_basis_points=_strict_int(rollout, "canary_basis_points"),
                native_default_enabled=_strict_bool(rollout, "native_default_enabled"),
                native_default_authorization=_optional_string(
                    rollout, "native_default_authorization"
                ),
            )
        except (KeyError, TypeError) as error:
            raise RolloutEvidenceError("malformed W8 adoption evidence") from error


@dataclass(frozen=True)
class RolloutSelection:
    mode: RolloutMode
    track: RolloutTrack
    engine: EngineSelection
    native_digest: str | None
    cohort_bucket: int | None
    reason: str

    def run_native(
        self,
        arguments: tuple[str, ...],
        *,
        timeout: float,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        """Launch the selected exact native inode, or reject a Python track."""
        if (
            self.engine.choice is not EngineChoice.RUST_NATIVE
            or self.engine.executable is None
            or self.native_digest is None
        ):
            raise NativeEngineUnavailable("rollout selection does not contain a native engine")
        return run_pinned_native(
            self.engine.executable,
            self.native_digest,
            arguments,
            timeout=timeout,
            cwd=cwd,
            environment=environment,
        )


def _string(value: Mapping[str, object], key: str) -> str:
    item = value[key]
    if not isinstance(item, str) or not item:
        raise TypeError
    return item


def _exact_keys(value: Mapping[str, object], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        raise RolloutEvidenceError(f"{label} must contain exactly {sorted(expected)!r}")


def _validate_evidence_ids(values: tuple[str, ...], *, label: str) -> None:
    if not values or len(values) > 64:
        raise RolloutEvidenceError(f"{label} requires 1 to 64 evidence identifiers")
    if any(not item or len(item) > 256 for item in values):
        raise RolloutEvidenceError(f"{label} evidence identifiers must contain 1 to 256 chars")
    if len(set(values)) != len(values):
        raise RolloutEvidenceError(f"{label} evidence identifiers must be unique")


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    item = value[key]
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        raise TypeError
    return item


def _strict_bool(value: Mapping[str, object], key: str) -> bool:
    item = value[key]
    if type(item) is not bool:
        raise TypeError
    return item


def _strict_int(value: Mapping[str, object], key: str) -> int:
    item = value[key]
    if isinstance(item, bool) or not isinstance(item, int):
        raise TypeError
    return item


def _wave_gate(value: object) -> WaveGate:
    if not isinstance(value, Mapping):
        raise TypeError
    _exact_keys(value, {"wave", "commit", "evidence_ids"}, label="prior wave")
    evidence_ids = value["evidence_ids"]
    if not isinstance(evidence_ids, list) or not all(
        isinstance(item, str) for item in evidence_ids
    ):
        raise TypeError
    return WaveGate(
        wave=_strict_int(value, "wave"),
        commit=_string(value, "commit"),
        evidence_ids=tuple(evidence_ids),
    )


def _host_artifact(value: object) -> HostArtifactPin:
    if not isinstance(value, Mapping):
        raise TypeError
    _exact_keys(
        value,
        {"host_class", "native_sha256", "capabilities_sha256"},
        label="host artifact",
    )
    return HostArtifactPin(
        host_class=_string(value, "host_class"),
        native_sha256=_string(value, "native_sha256"),
        capabilities_sha256=_string(value, "capabilities_sha256"),
    )


def canonical_json_digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    except OSError as error:
        raise NativeEngineUnavailable("native artifact cannot be read") from error
    finally:
        with suppress(OSError):
            os.lseek(descriptor, 0, os.SEEK_SET)
    return "sha256:" + digest.hexdigest()


def run_pinned_native(
    executable: Path,
    expected_native_digest: str,
    arguments: tuple[str, ...],
    *,
    timeout: float,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Execute an exact opened native inode through Linux ``/proc/self/fd``.

    Callers use this for every native launch instead of reopening the bundle
    pathname after verification.  It is intentionally a local Linux helper;
    unsupported hosts remain on the Python reference.
    """
    if _DIGEST_RE.fullmatch(expected_native_digest) is None:
        raise NativeEngineUnavailable("native artifact digest pin is malformed")
    if timeout <= 0:
        raise NativeEngineUnavailable("native execution timeout must be positive")
    if any(not isinstance(item, str) or "\0" in item for item in arguments):
        raise NativeEngineUnavailable("native execution arguments are invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(executable, flags)
    except OSError as error:
        raise NativeEngineUnavailable("pinned native artifact is unavailable or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
            raise NativeEngineUnavailable("pinned native artifact is not a regular executable")
        if metadata.st_mode & 0o022:
            raise NativeEngineUnavailable("pinned native artifact is group/world writable")
        if _sha256_fd(descriptor) != expected_native_digest:
            raise NativeEngineUnavailable("native artifact does not match the pinned release")
        proc_path = f"/proc/self/fd/{descriptor}"
        if not Path(proc_path).exists():
            raise NativeEngineUnavailable("descriptor execution is unavailable on this host")
        try:
            return subprocess.run(
                [proc_path, *arguments],
                check=False,
                capture_output=True,
                timeout=timeout,
                pass_fds=(descriptor,),
                cwd=cwd,
                env=None if environment is None else dict(environment),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise NativeEngineUnavailable("pinned native execution failed") from error
    finally:
        os.close(descriptor)


def probe_native_capabilities(
    executable: Path,
    *,
    expected_native_digest: str | None = None,
) -> tuple[EngineCapabilities, str]:
    """Read bounded native metadata; this never starts a wrapped command."""
    if expected_native_digest is None:
        raise NativeEngineUnavailable("native capability probe requires an artifact digest pin")
    completed = run_pinned_native(
        executable,
        expected_native_digest,
        ("capabilities", "--json"),
        timeout=5,
        cwd=Path("/"),
        environment={"LANG": "C.UTF-8", "PATH": os.defpath},
    )
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > _MAX_CAPABILITY_BYTES
    ):
        raise NativeEngineUnavailable("native capability probe was not clean and bounded")
    try:
        document = json.loads(completed.stdout)
        if not isinstance(document, dict):
            raise TypeError
        capabilities = EngineCapabilities.from_dict(document)
    except (ValueError, TypeError) as error:
        raise NativeEngineUnavailable("native capability document is invalid") from error
    return capabilities, canonical_json_digest(document)


def cohort_bucket(
    release_manifest_digest: str,
    host_class: HostClass,
    canary_key: str,
) -> int:
    """Map one caller-owned stable key into a deterministic 0..9999 cohort."""
    if (
        _DIGEST_RE.fullmatch(release_manifest_digest) is None
        or not canary_key
        or len(canary_key) > 4096
    ):
        raise RolloutEvidenceError("canary cohort inputs are invalid")
    material = "\0".join((release_manifest_digest, host_class.identifier, canary_key)).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") % 10_000


def _python_selection(reason: str) -> EngineSelection:
    return EngineSelection(EngineChoice.PYTHON_REFERENCE, None, reason)


def _native_selection(
    executable: Path,
    host_class: HostClass,
    requirement: CapabilityRequirement,
    *,
    expected_native_digest: str,
    expected_capabilities_digest: str,
) -> EngineSelection:
    capabilities, observed_digest = probe_native_capabilities(
        executable,
        expected_native_digest=expected_native_digest,
    )
    if observed_digest != expected_capabilities_digest:
        raise NativeEngineUnavailable("native capabilities do not match the pinned release")
    if capabilities.engine.platform != host_class.native_platform:
        raise NativeEngineUnavailable("native platform does not match the selected host class")
    negotiate_capabilities(capabilities, requirement)
    return EngineSelection(
        EngineChoice.RUST_NATIVE,
        Path(os.path.abspath(executable)),
        "pinned native artifact passed capability negotiation",
    )


def select_rollout_engines(
    evidence: RolloutEvidence,
    *,
    mode: RolloutMode | str,
    host_class: HostClass,
    native_executable: Path,
    requirement: CapabilityRequirement | None = None,
    canary_key: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> RolloutSelection:
    """Select primary/shadow engines without widening caller authority.

    Bypass is unconditional. Shadow may execute once through an eligible native
    engine while the adapter preserves its ordinary, unprojected result; it
    never requests a second execution for comparison. Enforce selects native
    solely for an authorized default or deterministic canary cohort.
    """
    values = os.environ if environment is None else environment
    enabled = values.get("OUTCTL_ENABLED")
    if enabled == "0" or mode == RolloutMode.BYPASS:
        return RolloutSelection(
            RolloutMode.BYPASS,
            RolloutTrack.PYTHON,
            _python_selection("rollback/bypass selected"),
            None,
            None,
            "break-glass path requires no rollout evidence or capture migration",
        )
    if enabled is not None and enabled not in {"0", "1"}:
        raise RolloutEvidenceError("OUTCTL_ENABLED must be '0' or '1'")
    try:
        rollout_mode = RolloutMode(mode)
    except ValueError as error:
        raise RolloutEvidenceError(f"unsupported rollout mode: {mode!r}") from error
    if evidence.release_manifest_digest != values.get(
        "OUTCTL_RELEASE_MANIFEST_DIGEST", evidence.release_manifest_digest
    ):
        raise RolloutEvidenceError("configured release manifest digest does not match evidence")
    artifact_pin = evidence.artifact_for(host_class.identifier)
    if artifact_pin is None:
        return RolloutSelection(
            rollout_mode,
            RolloutTrack.PYTHON,
            _python_selection("host class is not enabled for this release"),
            None,
            None,
            "unsupported host classes fail back to the Python reference",
        )
    if not evidence.pre_shadow_passed:
        return RolloutSelection(
            rollout_mode,
            RolloutTrack.PYTHON,
            _python_selection("W8 pre-shadow gates are incomplete"),
            None,
            None,
            "clean install, host conformance, and rollback must all pass",
        )
    if rollout_mode is RolloutMode.SHADOW:
        required = CapabilityRequirement() if requirement is None else requirement
        native = _native_selection(
            native_executable,
            host_class,
            required,
            expected_native_digest=artifact_pin.native_sha256,
            expected_capabilities_digest=artifact_pin.capabilities_sha256,
        )
        return RolloutSelection(
            rollout_mode,
            RolloutTrack.SHADOW,
            native,
            artifact_pin.native_sha256,
            None,
            "native executes once; shadow exposure preserves the ordinary result",
        )
    if not evidence.pre_canary_passed:
        return RolloutSelection(
            rollout_mode,
            RolloutTrack.PYTHON,
            _python_selection("native canary gate is incomplete"),
            None,
            None,
            "shadow evidence must pass before native canary selection",
        )
    if evidence.native_default_enabled:
        if not evidence.default_passed:
            raise RolloutEvidenceError("native default requested before the canary gate passed")
        required = CapabilityRequirement() if requirement is None else requirement
        native = _native_selection(
            native_executable,
            host_class,
            required,
            expected_native_digest=artifact_pin.native_sha256,
            expected_capabilities_digest=artifact_pin.capabilities_sha256,
        )
        return RolloutSelection(
            rollout_mode,
            RolloutTrack.NATIVE_DEFAULT,
            native,
            artifact_pin.native_sha256,
            None,
            "all W0-W8 gates and the external default authorization passed",
        )
    if evidence.canary_basis_points and canary_key is not None:
        bucket = cohort_bucket(evidence.release_manifest_digest, host_class, canary_key)
        if bucket < evidence.canary_basis_points:
            required = CapabilityRequirement() if requirement is None else requirement
            native = _native_selection(
                native_executable,
                host_class,
                required,
                expected_native_digest=artifact_pin.native_sha256,
                expected_capabilities_digest=artifact_pin.capabilities_sha256,
            )
            return RolloutSelection(
                rollout_mode,
                RolloutTrack.CANARY,
                native,
                artifact_pin.native_sha256,
                bucket,
                "caller key is in the deterministic native canary cohort",
            )
        return RolloutSelection(
            rollout_mode,
            RolloutTrack.PYTHON,
            _python_selection("caller key is outside the native canary cohort"),
            None,
            bucket,
            "non-canary enforce traffic remains on the Python reference",
        )
    return RolloutSelection(
        rollout_mode,
        RolloutTrack.PYTHON,
        _python_selection("native default is disabled"),
        None,
        None,
        "no authorized native canary/default applies",
    )


__all__ = [
    "HostClass",
    "HostArtifactPin",
    "RolloutEvidence",
    "RolloutEvidenceError",
    "RolloutSelection",
    "RolloutMode",
    "RolloutTrack",
    "WaveGate",
    "canonical_json_digest",
    "cohort_bucket",
    "probe_native_capabilities",
    "run_pinned_native",
    "select_rollout_engines",
]
