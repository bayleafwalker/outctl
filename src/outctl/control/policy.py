"""Deterministic policy compilation for the v2 Python control plane.

Source policy is data, not authority.  This module can narrow disclosure and
capture behavior into an immutable :class:`PolicySnapshot`; it cannot grant
execution, retries, or lifecycle transitions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, NoReturn, SupportsIndex, cast

import yaml  # type: ignore[import-untyped]

from outctl.control.contracts import (
    CaptureCommitment,
    CaptureDurability,
    PolicyBinding,
    PolicyCacheEntry,
    PolicySnapshot,
    SinkPolicy,
)

MAX_POLICY_SOURCE_BYTES: Final = 1_048_576
MAX_VALIDITY_MS: Final = 86_400_000
MAX_CACHE_AGE_MS: Final = 86_400_000
MAX_SECRET_REFS: Final = 64
MAX_SECRET_BYTES: Final = 16_384
MAX_REGISTERED_SECRET_BYTES: Final = 262_144

_SCHEMA_VERSION: Final = "vuoro.outctl.policy-source/v1"
_SNAPSHOT_SCHEMA_VERSION: Final = "vuoro.outctl.policy-snapshot/v2"
_SINK_NAMES: Final = frozenset({"model", "runner", "audit-receipt", "handoff"})
_TRUST_DOMAINS: Final = ("trusted-local", "restricted", "export", "metadata-only")
_DISCLOSURES: Final = frozenset({"safe-unredacted", "sanitized", "metadata-only", "deny"})
_CLASSIFICATIONS: Final = frozenset({"public", "internal", "confidential", "secret"})
_SECRET_REF_RE: Final = re.compile(r"^secret://[A-Za-z0-9._:/-]+$")
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")


class PolicyCompileError(ValueError):
    """Raised when policy source cannot safely compile to a snapshot."""


class PolicySourcePathError(PolicyCompileError):
    """Raised when a source path is missing or crosses the policy root."""


class SecretRegistryError(ValueError):
    """Raised without including protected values in its message."""


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise PolicyCompileError("policy source contains a non-scalar mapping key") from exc
        if duplicate:
            raise PolicyCompileError("policy source contains a duplicate mapping key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class ClaimProvenance:
    """Non-secret evidence identifying who asserted a commissioning claim."""

    name: Literal["trust_domain", "commissioned"]
    value: str | bool
    issuer: str
    evidence_ref: str
    evidence_digest: str

    def __post_init__(self) -> None:
        if self.name not in {"trust_domain", "commissioned"}:
            raise PolicyCompileError("commissioning claim name is unsupported")
        if (
            not self.issuer
            or len(self.issuer) > 128
            or not self.evidence_ref
            or len(self.evidence_ref) > 512
            or self.evidence_ref.startswith("secret://")
        ):
            raise PolicyCompileError("commissioning claim provenance must be explicit")
        if _DIGEST_RE.fullmatch(self.evidence_digest) is None:
            raise PolicyCompileError("commissioning evidence digest must be sha256:<hex>")
        if self.name == "trust_domain":
            if not isinstance(self.value, str) or self.value not in _TRUST_DOMAINS:
                raise PolicyCompileError("trust-domain claim has an invalid type or value")
        elif type(self.value) is not bool:
            raise PolicyCompileError("commissioned claim must be a boolean")

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value,
            "issuer": self.issuer,
            "evidence_ref": self.evidence_ref,
            "evidence_digest": self.evidence_digest,
        }

    def public_metadata(self) -> ClaimProvenanceRecord:
        """Return the raw-free evidence binding included in source provenance."""
        return ClaimProvenanceRecord(
            self.name, self.issuer, self.evidence_ref, self.evidence_digest
        )


@dataclass(frozen=True)
class CommissioningContext:
    """Explicit, replayable facts supplied by the commissioning authority."""

    session_id: str
    trust_domain: str
    commissioned: bool
    issued_at: str
    valid_for_ms: int
    claims: tuple[ClaimProvenance, ...]

    def __post_init__(self) -> None:
        if not self.session_id or len(self.session_id) > 256:
            raise PolicyCompileError("session_id must be non-empty")
        if self.trust_domain not in _TRUST_DOMAINS:
            raise PolicyCompileError("commissioning trust domain is unsupported")
        if type(self.commissioned) is not bool:
            raise PolicyCompileError("commissioned must be a boolean")
        if self.trust_domain == "trusted-local" and not self.commissioned:
            raise PolicyCompileError("trusted-local commissioning must be explicit")
        _bounded_int(self.valid_for_ms, "valid_for_ms", maximum=MAX_VALIDITY_MS)
        _canonical_timestamp(self.issued_at)
        claims = {claim.name: claim for claim in self.claims}
        if len(claims) != len(self.claims):
            raise PolicyCompileError("commissioning claim names must be unique")
        if set(claims) != {"trust_domain", "commissioned"}:
            raise PolicyCompileError("trust_domain and commissioned claim provenance are required")
        if claims["trust_domain"].value != self.trust_domain:
            raise PolicyCompileError("trust-domain claim contradicts commissioning context")
        if claims["commissioned"].value is not self.commissioned:
            raise PolicyCompileError("commissioned claim contradicts commissioning context")


@dataclass(frozen=True)
class PolicyDiagnostic:
    severity: Literal["error", "info"]
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message}


@dataclass(frozen=True)
class ClaimProvenanceRecord:
    """The immutable non-secret subset of one commissioning claim."""

    name: str
    issuer: str
    evidence_ref: str
    evidence_digest: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "issuer": self.issuer,
            "evidence_ref": self.evidence_ref,
            "evidence_digest": self.evidence_digest,
        }


@dataclass(frozen=True)
class CommissioningProvenance:
    """Immutable raw-free evidence bindings cryptographically bound to a snapshot."""

    claims: tuple[ClaimProvenanceRecord, ...]
    digest: str

    def to_dict(self) -> dict[str, object]:
        return {"claims": [claim.to_dict() for claim in self.claims], "digest": self.digest}


@dataclass(frozen=True)
class CompiledPolicy:
    """A frozen engine snapshot and its non-secret commissioning provenance."""

    snapshot: PolicySnapshot
    provenance: CommissioningProvenance

    def to_dict(self) -> dict[str, object]:
        return {"snapshot": self.snapshot.to_dict(), "provenance": self.provenance.to_dict()}


@dataclass(frozen=True)
class PolicyLintResult:
    valid: bool
    diagnostics: tuple[PolicyDiagnostic, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass(frozen=True)
class PolicyExplanation:
    """A bounded, secret-free explanation of a compiled snapshot."""

    snapshot_id: str
    policy_ref: str
    trust_domain: str
    commissioned: bool
    sink_actions: tuple[tuple[str, str], ...]
    capture_commitment: str
    capture_required: bool
    commissioning_provenance: CommissioningProvenance
    execution_authority: Literal["external-runner"] = "external-runner"
    can_authorize_execution: Literal[False] = False

    def to_dict(self) -> dict[str, object]:
        return {
            "snapshot_id": self.snapshot_id,
            "policy_ref": self.policy_ref,
            "trust_domain": self.trust_domain,
            "commissioned": self.commissioned,
            "sink_actions": [
                {"name": name, "disclosure": disclosure} for name, disclosure in self.sink_actions
            ],
            "capture_commitment": self.capture_commitment,
            "capture_required": self.capture_required,
            "commissioning_provenance": self.commissioning_provenance.to_dict(),
            "execution_authority": self.execution_authority,
            "can_authorize_execution": self.can_authorize_execution,
        }


class ProtectedSecretRegistry:
    """Process-memory-only exact values addressed by opaque ``secret://`` refs.

    The registry deliberately offers no serializer.  Its representation,
    errors, and ref listing never include exact values.
    """

    __slots__ = ("_total_bytes", "_values")

    def __init__(self) -> None:
        self._values: dict[str, bytearray] = {}
        self._total_bytes = 0

    def __repr__(self) -> str:
        return f"ProtectedSecretRegistry(refs={len(self._values)}, bytes=<protected>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("protected secret registries cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("protected secret registries cannot be serialized")

    @property
    def refs(self) -> tuple[str, ...]:
        return tuple(sorted(self._values))

    def register(self, ref: str, value: str | bytes) -> None:
        if not isinstance(ref, str) or _SECRET_REF_RE.fullmatch(ref) is None:
            raise SecretRegistryError("secret reference must use the protected secret:// form")
        if ref in self._values:
            raise SecretRegistryError("secret reference is already registered")
        if len(self._values) >= MAX_SECRET_REFS:
            raise SecretRegistryError("secret registry reference limit exceeded")
        if isinstance(value, str):
            encoded = value.encode("utf-8")
        elif isinstance(value, bytes):
            encoded = value
        else:
            raise SecretRegistryError("secret value must be text or bytes")
        if not encoded:
            raise SecretRegistryError("secret value must be non-empty")
        if len(encoded) > MAX_SECRET_BYTES:
            raise SecretRegistryError("secret value exceeds the per-value limit")
        if self._total_bytes + len(encoded) > MAX_REGISTERED_SECRET_BYTES:
            raise SecretRegistryError("secret registry aggregate limit exceeded")
        self._values[ref] = bytearray(encoded)
        self._total_bytes += len(encoded)

    def resolve(self, ref: str) -> bytes:
        try:
            return bytes(self._values[ref])
        except (KeyError, TypeError) as exc:
            raise SecretRegistryError("secret reference is not registered") from exc

    def unregister(self, ref: str) -> None:
        try:
            value = self._values.pop(ref)
        except (KeyError, TypeError) as exc:
            raise SecretRegistryError("secret reference is not registered") from exc
        self._total_bytes -= len(value)
        value[:] = b"\x00" * len(value)

    def clear(self) -> None:
        for value in self._values.values():
            value[:] = b"\x00" * len(value)
        self._values.clear()
        self._total_bytes = 0


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyCompileError("policy material is not canonical JSON data") from exc


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PolicyCompileError(f"{label} must be an object with string keys")
    return cast(dict[str, object], value)


def _exact_keys(
    value: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
    label: str,
) -> None:
    keys = set(value)
    if keys - required - (optional or set()):
        raise PolicyCompileError(f"{label} contains unsupported keys")
    if required - keys:
        raise PolicyCompileError(f"{label} is missing required keys")


def _non_empty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyCompileError(f"{label} must be a non-empty string")
    return value


def _bounded_int(value: object, label: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyCompileError(f"{label} must be an integer")
    if not 1 <= value <= maximum:
        raise PolicyCompileError(f"{label} is outside the supported bounds")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise PolicyCompileError(f"{label} must be a boolean")
    return value


def _canonical_timestamp(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyCompileError("issued_at must be an explicit ISO-8601 timestamp")
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyCompileError("issued_at must be an explicit ISO-8601 timestamp") from exc
    if observed.tzinfo is None:
        raise PolicyCompileError("issued_at must include a timezone")
    return observed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _read_policy_source(policy_root: Path, source_path: str | Path) -> bytes:
    relative = Path(source_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise PolicySourcePathError("policy source must be a safe relative path")
    try:
        root = policy_root.resolve(strict=True)
    except OSError as exc:
        raise PolicySourcePathError("policy root cannot be resolved safely") from exc
    if not root.is_dir():
        raise PolicySourcePathError("policy root must be a directory")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(root, flags)
    except OSError as exc:
        raise PolicySourcePathError("policy root cannot be opened safely") from exc
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            file_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=directory_fd)
        try:
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_POLICY_SOURCE_BYTES:
                raise PolicySourcePathError("policy source must be a bounded regular file")
            chunks: list[bytes] = []
            remaining = MAX_POLICY_SOURCE_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
            if len(body) > MAX_POLICY_SOURCE_BYTES:
                raise PolicySourcePathError("policy source exceeds the byte limit")
            return body
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise PolicySourcePathError("policy source cannot be opened safely") from exc
    finally:
        os.close(directory_fd)


def _parse_source(body: bytes) -> dict[str, object]:
    try:
        text = body.decode("utf-8")
        loaded = yaml.load(text, Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyCompileError("policy source is not valid UTF-8 YAML") from exc
    return _mapping(loaded, "policy source")


def _validated_source(value: dict[str, object]) -> dict[str, object]:
    _exact_keys(
        value,
        required={"schema_version", "policy_ref", "cache", "sinks", "capture"},
        label="policy source",
    )
    if value["schema_version"] != _SCHEMA_VERSION:
        raise PolicyCompileError("policy source schema_version is unsupported")
    policy_ref = _non_empty_string(value["policy_ref"], "policy_ref")
    if not policy_ref.startswith("policy://"):
        raise PolicyCompileError("policy_ref must use the policy:// scheme")

    cache = _mapping(value["cache"], "cache")
    _exact_keys(cache, required={"max_age_ms"}, label="cache")
    max_age_ms = _bounded_int(cache["max_age_ms"], "cache.max_age_ms", maximum=MAX_CACHE_AGE_MS)

    capture = _mapping(value["capture"], "capture")
    _exact_keys(capture, required={"commitment", "durability", "required"}, label="capture")
    commitment = _non_empty_string(capture["commitment"], "capture.commitment")
    durability = _non_empty_string(capture["durability"], "capture.durability")
    capture_required = _boolean(capture["required"], "capture.required")
    try:
        CaptureCommitment(commitment)
        CaptureDurability(durability)
    except ValueError as exc:
        raise PolicyCompileError(
            "capture contains an unsupported commitment or durability"
        ) from exc

    raw_sinks = value["sinks"]
    if not isinstance(raw_sinks, list) or not raw_sinks:
        raise PolicyCompileError("sinks must be a non-empty list")
    if len(raw_sinks) > len(_SINK_NAMES):
        raise PolicyCompileError("sinks exceeds the supported target count")
    sinks: list[dict[str, object]] = []
    names: set[str] = set()
    for raw_sink in raw_sinks:
        sink = _mapping(raw_sink, "sink")
        _exact_keys(
            sink,
            required={"name", "trust_domain", "disclosure", "redaction_required"},
            optional={"classification_ceiling"},
            label="sink",
        )
        name = _non_empty_string(sink["name"], "sink.name")
        if name not in _SINK_NAMES:
            raise PolicyCompileError("sink name is not a supported RunRequest target")
        if name in names:
            raise PolicyCompileError("sink names must be unique")
        names.add(name)
        trust_domain = _non_empty_string(sink["trust_domain"], "sink.trust_domain")
        disclosure = _non_empty_string(sink["disclosure"], "sink.disclosure")
        if trust_domain not in _TRUST_DOMAINS or disclosure not in _DISCLOSURES:
            raise PolicyCompileError("sink contains an unsupported trust or disclosure value")
        redaction_required = _boolean(sink["redaction_required"], "sink.redaction_required")
        normalized: dict[str, object] = {
            "name": name,
            "trust_domain": trust_domain,
            "disclosure": disclosure,
            "redaction_required": redaction_required,
        }
        if "classification_ceiling" in sink:
            ceiling = _non_empty_string(
                sink["classification_ceiling"], "sink.classification_ceiling"
            )
            if ceiling not in _CLASSIFICATIONS:
                raise PolicyCompileError("sink classification ceiling is unsupported")
            normalized["classification_ceiling"] = ceiling
        try:
            SinkPolicy(
                name=name,
                trust_domain=trust_domain,
                disclosure=disclosure,
                redaction_required=redaction_required,
                classification_ceiling=cast(str | None, normalized.get("classification_ceiling")),
            )
        except ValueError as exc:
            raise PolicyCompileError("sink trust/disclosure combination is invalid") from exc
        sinks.append(normalized)

    return {
        "schema_version": _SCHEMA_VERSION,
        "policy_ref": policy_ref,
        "cache": {"max_age_ms": max_age_ms},
        "sinks": sorted(sinks, key=lambda sink: cast(str, sink["name"])),
        "capture": {
            "commitment": commitment,
            "durability": durability,
            "required": capture_required,
        },
    }


def _validate_contextual_policy(
    source: Mapping[str, object], context: CommissioningContext
) -> None:
    allowed_by_context = {
        "trusted-local": set(_TRUST_DOMAINS),
        "restricted": {"restricted", "export", "metadata-only"},
        "export": {"export", "metadata-only"},
        "metadata-only": {"metadata-only"},
    }[context.trust_domain]
    for sink in cast(list[dict[str, object]], source["sinks"]):
        if sink["trust_domain"] not in allowed_by_context:
            raise PolicyCompileError("sink policy would widen the commissioning trust domain")
    capture = cast(dict[str, object], source["capture"])
    if context.trust_domain == "trusted-local" and (
        capture["required"] is not True
        or capture["commitment"] not in {"host-persistent", "replicated"}
    ):
        raise PolicyCompileError("trusted-local policy requires persistent required capture")
    cache = cast(dict[str, object], source["cache"])
    if cast(int, cache["max_age_ms"]) > context.valid_for_ms:
        raise PolicyCompileError("cache max_age_ms cannot outlive snapshot validity")


def commissioning_provenance_digest(context: CommissioningContext) -> str:
    """Digest sorted non-secret claim provenance independently of the snapshot."""
    return _sha256([claim.to_dict() for claim in _provenance_claims(context)])


def _provenance_claims(context: CommissioningContext) -> list[ClaimProvenanceRecord]:
    return [
        claim.public_metadata() for claim in sorted(context.claims, key=lambda claim: claim.name)
    ]


def canonical_policy_material(snapshot: PolicySnapshot | Mapping[str, object]) -> dict[str, object]:
    """Return the cross-language semantic material bound by ``policy_digest``.

    Identity and cache lookup fields are intentionally excluded.  Sinks are
    sorted by name so authoring order cannot change the engine binding.
    """
    value = snapshot.to_dict() if isinstance(snapshot, PolicySnapshot) else dict(snapshot)
    try:
        sinks = value["sinks"]
        cache = cast(Mapping[str, object], value["cache"])
        if not isinstance(sinks, list):
            raise TypeError
        sorted_sinks = sorted(
            (cast(dict[str, object], sink) for sink in sinks),
            key=lambda sink: cast(str, sink["name"]),
        )
        return {
            "schema_version": value["schema_version"],
            "source": value["source"],
            "session": value["session"],
            "sinks": sorted_sinks,
            "capture": value["capture"],
            "execution_authority": value["execution_authority"],
            "issued_at": value["issued_at"],
            "expires_at": value["expires_at"],
            "cache": {"owner": cache["owner"], "max_age_ms": cache["max_age_ms"]},
        }
    except (KeyError, TypeError) as exc:
        raise PolicyCompileError("snapshot-like policy material is incomplete") from exc


def compile_policy_source(
    policy_root: str | Path,
    source_path: str | Path,
    context: CommissioningContext,
) -> CompiledPolicy:
    """Load and compile one root-confined source policy deterministically."""
    body = _read_policy_source(Path(policy_root), source_path)
    source = _validated_source(_parse_source(body))
    _validate_contextual_policy(source, context)
    relative = Path(source_path)
    source_ref = f"policy-source://{relative.as_posix()}"
    provenance_records = _provenance_claims(context)
    provenance_claims = [claim.to_dict() for claim in provenance_records]
    provenance = CommissioningProvenance(
        claims=tuple(provenance_records),
        digest=_sha256(provenance_claims),
    )
    source_digest = _sha256({"policy": source, "commissioning_claims": provenance_claims})
    issued_at = _canonical_timestamp(context.issued_at)
    issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    expires_at = (
        (issued + timedelta(milliseconds=context.valid_for_ms))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    cache_data = cast(dict[str, object], source["cache"])
    sinks_data = cast(list[dict[str, object]], source["sinks"])
    capture_data = cast(dict[str, object], source["capture"])
    document: dict[str, object] = {
        "schema_version": _SNAPSHOT_SCHEMA_VERSION,
        "source": {"ref": source_ref, "digest": source_digest},
        "cache": {
            "owner": "python-policy-control",
            "max_age_ms": cache_data["max_age_ms"],
        },
        "session": {
            "session_id": context.session_id,
            "trust_domain": context.trust_domain,
            "commissioned": context.commissioned,
        },
        "sinks": sinks_data,
        "capture": capture_data,
        "execution_authority": {
            "owner": "external-runner",
            "can_authorize_execution": False,
            "can_retry": False,
        },
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    digest = _sha256(canonical_policy_material(document))
    snapshot_id = "snapshot-" + digest.removeprefix("sha256:")[:32]
    binding = PolicyBinding(snapshot_id, cast(str, source["policy_ref"]), digest)
    cache = PolicyCacheEntry(
        f"policy-cache://snapshot/{snapshot_id}",
        binding,
        "python-policy-control",
        cast(int, cache_data["max_age_ms"]),
    )
    sinks = tuple(
        SinkPolicy(
            name=cast(str, sink["name"]),
            trust_domain=cast(str, sink["trust_domain"]),
            disclosure=cast(str, sink["disclosure"]),
            redaction_required=cast(bool, sink["redaction_required"]),
            classification_ceiling=cast(str | None, sink.get("classification_ceiling")),
        )
        for sink in sinks_data
    )
    try:
        snapshot = PolicySnapshot(
            binding=binding,
            source_ref=source_ref,
            source_digest=source_digest,
            cache=cache,
            session_id=context.session_id,
            trust_domain=context.trust_domain,
            commissioned=context.commissioned,
            sinks=sinks,
            capture_commitment=CaptureCommitment(cast(str, capture_data["commitment"])),
            capture_durability=CaptureDurability(cast(str, capture_data["durability"])),
            capture_required=cast(bool, capture_data["required"]),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except ValueError as exc:
        raise PolicyCompileError("compiled policy violates the frozen snapshot contract") from exc
    return CompiledPolicy(snapshot=snapshot, provenance=provenance)


def lint_policy_source(
    policy_root: str | Path,
    source_path: str | Path,
    context: CommissioningContext,
) -> PolicyLintResult:
    """Return bounded diagnostics; never copy source values into diagnostics."""
    try:
        compiled = compile_policy_source(policy_root, source_path, context)
    except PolicySourcePathError:
        return PolicyLintResult(
            False,
            (
                PolicyDiagnostic(
                    "error", "unsafe-source-path", "policy source is not safely readable"
                ),
            ),
        )
    except (PolicyCompileError, OSError):
        return PolicyLintResult(
            False,
            (PolicyDiagnostic("error", "invalid-policy", "policy source did not pass validation"),),
        )
    return PolicyLintResult(
        True,
        (
            PolicyDiagnostic(
                "info",
                "compiled",
                f"compiled {len(compiled.snapshot.sinks)} sink action(s) "
                "with external execution authority",
            ),
        ),
    )


def explain_policy(compiled: CompiledPolicy) -> PolicyExplanation:
    """Explain only non-sensitive policy decisions from a compiled snapshot."""
    snapshot = compiled.snapshot
    return PolicyExplanation(
        snapshot_id=snapshot.binding.snapshot_id,
        policy_ref=snapshot.binding.ref,
        trust_domain=snapshot.trust_domain,
        commissioned=snapshot.commissioned,
        sink_actions=tuple((sink.name, sink.disclosure) for sink in snapshot.sinks),
        capture_commitment=snapshot.capture_commitment.value,
        capture_required=snapshot.capture_required,
        commissioning_provenance=compiled.provenance,
    )


__all__ = [
    "ClaimProvenance",
    "ClaimProvenanceRecord",
    "CommissioningProvenance",
    "CommissioningContext",
    "CompiledPolicy",
    "MAX_CACHE_AGE_MS",
    "MAX_POLICY_SOURCE_BYTES",
    "MAX_REGISTERED_SECRET_BYTES",
    "MAX_SECRET_BYTES",
    "MAX_SECRET_REFS",
    "MAX_VALIDITY_MS",
    "PolicyCompileError",
    "PolicyDiagnostic",
    "PolicyExplanation",
    "PolicyLintResult",
    "PolicySourcePathError",
    "ProtectedSecretRegistry",
    "SecretRegistryError",
    "canonical_policy_material",
    "commissioning_provenance_digest",
    "compile_policy_source",
    "explain_policy",
    "lint_policy_source",
]
