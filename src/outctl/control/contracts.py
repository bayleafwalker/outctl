"""Typed, side-effect-free models for the frozen v2 control boundary.

These models cover the policy/capability data exchanged with a future native
engine.  They validate the invariants that are useful before an engine is
selected, but intentionally do not compile policy or execute commands.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, cast

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")


class ControlContractError(ValueError):
    """Raised when a v2 control-plane value is structurally unsafe."""


class CapabilityNegotiationError(ControlContractError):
    """Raised when a selected engine cannot satisfy a request."""


class EngineFeature(StrEnum):
    """Features that may be negotiated before a native call is made."""

    DIRECT_ARGV = "direct_argv"
    EXPLICIT_SHELL = "explicit_shell"
    STDIN = "stdin"
    RETRIEVAL = "retrieval"
    ONE_VERSION_BACK_READ = "one_version_back_read"


class CaptureCommitment(StrEnum):
    MEMORY_ONLY = "memory-only"
    PROCESS_LOCAL = "process-local"
    HOST_PERSISTENT = "host-persistent"
    REPLICATED = "replicated"


class CaptureDurability(StrEnum):
    NONE = "none"
    HOST = "host"
    REPLICA = "replica"
    AUTHORITATIVE = "authoritative"


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ControlContractError(f"{label} must be a sha256:<hex> digest")
    return value


def _non_empty(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ControlContractError(f"{label} must be non-empty")
    return value


def _timestamp(value: str, label: str) -> str:
    _non_empty(value, label)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControlContractError(f"{label} must be an ISO-8601 timestamp") from exc
    return value


def _positive_int(value: object, label: str) -> int:
    """Return a JSON integer field with a useful type error."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ControlContractError(f"{label} must be an integer")
    return value


def _string_field(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ControlContractError(f"{label} must be a non-empty string")
    return value


def _bool_field(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ControlContractError(f"{label} must be a boolean")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ControlContractError(f"{label} must be a list of non-empty strings")
    return tuple(value)


@dataclass(frozen=True)
class PolicyBinding:
    """The exact snapshot identity echoed by request, result, and manifest."""

    snapshot_id: str
    ref: str
    digest: str

    def __post_init__(self) -> None:
        _non_empty(self.snapshot_id, "snapshot_id")
        _non_empty(self.ref, "policy ref")
        _digest(self.digest, "policy digest")

    def to_dict(self) -> dict[str, str]:
        return {"snapshot_id": self.snapshot_id, "ref": self.ref, "digest": self.digest}

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> PolicyBinding:
        try:
            return cls(
                _string_field(value["snapshot_id"], "snapshot_id"),
                _string_field(value["ref"], "policy ref"),
                _string_field(value["digest"], "policy digest"),
            )
        except KeyError as exc:
            raise ControlContractError(f"policy binding is missing {exc.args[0]!r}") from exc


@dataclass(frozen=True)
class PolicyCacheEntry:
    """An immutable cache index record owned by the Python control plane."""

    key: str
    binding: PolicyBinding
    owner: str
    max_age_ms: int

    def __post_init__(self) -> None:
        _non_empty(self.key, "cache key")
        if self.owner != "python-policy-control":
            raise ControlContractError("policy cache owner must be python-policy-control")
        if self.max_age_ms < 1:
            raise ControlContractError("policy cache max_age_ms must be positive")

    def to_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "snapshot_id": self.binding.snapshot_id,
            "owner": self.owner,
            "max_age_ms": self.max_age_ms,
        }


@dataclass(frozen=True)
class EngineIdentity:
    id: str
    version: str
    platform: str

    def __post_init__(self) -> None:
        _non_empty(self.id, "engine id")
        _non_empty(self.version, "engine version")
        _non_empty(self.platform, "engine platform")

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "version": self.version, "platform": self.platform}


@dataclass(frozen=True)
class EngineCapabilities:
    """Capabilities advertised by a selected engine, without execution."""

    engine: EngineIdentity
    run_request_versions: tuple[str, ...]
    policy_snapshot_versions: tuple[str, ...]
    run_result_versions: tuple[str, ...]
    capture_manifest_versions: tuple[str, ...]
    direct_argv: bool
    explicit_shell: bool
    stdin: bool
    retrieval: bool
    one_version_back_read: bool
    max_argv_items: int
    max_capture_bytes: int
    max_projection_bytes: int

    def __post_init__(self) -> None:
        if not self.direct_argv:
            raise ControlContractError("direct argv is the frozen baseline capability")
        if not self.one_version_back_read:
            raise ControlContractError("one-version-back read is the frozen baseline capability")
        for label, value in (
            ("max_argv_items", self.max_argv_items),
            ("max_capture_bytes", self.max_capture_bytes),
            ("max_projection_bytes", self.max_projection_bytes),
        ):
            if value < 1:
                raise ControlContractError(f"{label} must be positive")

    def supports(self, feature: EngineFeature) -> bool:
        return {
            EngineFeature.DIRECT_ARGV: self.direct_argv,
            EngineFeature.EXPLICIT_SHELL: self.explicit_shell,
            EngineFeature.STDIN: self.stdin,
            EngineFeature.RETRIEVAL: self.retrieval,
            EngineFeature.ONE_VERSION_BACK_READ: self.one_version_back_read,
        }[feature]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "vuoro.outctl.engine-capabilities/v2",
            "engine": self.engine.to_dict(),
            "contract_versions": {
                "run_request": list(self.run_request_versions),
                "policy_snapshot": list(self.policy_snapshot_versions),
                "run_result": list(self.run_result_versions),
                "capture_manifest": list(self.capture_manifest_versions),
            },
            "features": {
                "direct_argv": self.direct_argv,
                "explicit_shell": self.explicit_shell,
                "stdin": self.stdin,
                "retrieval": self.retrieval,
                "one_version_back_read": self.one_version_back_read,
            },
            "limits": {
                "max_argv_items": self.max_argv_items,
                "max_capture_bytes": self.max_capture_bytes,
                "max_projection_bytes": self.max_projection_bytes,
            },
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> EngineCapabilities:
        if value.get("schema_version") != "vuoro.outctl.engine-capabilities/v2":
            raise ControlContractError("unsupported engine capabilities schema")
        try:
            engine_value = value["engine"]
            versions = value["contract_versions"]
            features = value["features"]
            limits = value["limits"]
            if not all(
                isinstance(item, dict) for item in (engine_value, versions, features, limits)
            ):
                raise TypeError
            engine_data = cast(dict[str, object], engine_value)
            version_data = cast(dict[str, object], versions)
            feature_data = cast(dict[str, object], features)
            limit_data = cast(dict[str, object], limits)
            return cls(
                EngineIdentity(
                    _string_field(engine_data["id"], "engine.id"),
                    _string_field(engine_data["version"], "engine.version"),
                    _string_field(engine_data["platform"], "engine.platform"),
                ),
                _string_tuple(version_data["run_request"], "contract_versions.run_request"),
                _string_tuple(version_data["policy_snapshot"], "contract_versions.policy_snapshot"),
                _string_tuple(version_data["run_result"], "contract_versions.run_result"),
                _string_tuple(
                    version_data["capture_manifest"], "contract_versions.capture_manifest"
                ),
                _bool_field(feature_data["direct_argv"], "features.direct_argv"),
                _bool_field(feature_data["explicit_shell"], "features.explicit_shell"),
                _bool_field(feature_data["stdin"], "features.stdin"),
                _bool_field(feature_data["retrieval"], "features.retrieval"),
                _bool_field(
                    feature_data["one_version_back_read"], "features.one_version_back_read"
                ),
                _positive_int(limit_data["max_argv_items"], "max_argv_items"),
                _positive_int(limit_data["max_capture_bytes"], "max_capture_bytes"),
                _positive_int(limit_data["max_projection_bytes"], "max_projection_bytes"),
            )
        except ControlContractError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlContractError("invalid engine capabilities document") from exc


@dataclass(frozen=True)
class CapabilityRequirement:
    """Features a caller must have before selecting an engine."""

    features: frozenset[EngineFeature] = frozenset({EngineFeature.DIRECT_ARGV})
    run_request_version: str = "v2"
    policy_snapshot_version: str = "v2"
    run_result_version: str = "v2"


@dataclass(frozen=True)
class NegotiatedCapabilities:
    engine: EngineCapabilities
    required: CapabilityRequirement

    @property
    def features(self) -> frozenset[EngineFeature]:
        return self.required.features


def negotiate_capabilities(
    capabilities: EngineCapabilities,
    required: CapabilityRequirement | Iterable[EngineFeature] | None = None,
) -> NegotiatedCapabilities:
    """Fail closed when an engine cannot satisfy a pinned feature request."""
    if required is None:
        required = CapabilityRequirement()
    requirement = (
        required
        if isinstance(required, CapabilityRequirement)
        else CapabilityRequirement(features=frozenset(required))
    )
    missing = sorted(
        feature.value for feature in requirement.features if not capabilities.supports(feature)
    )
    contract_mismatches = [
        ("run_request", requirement.run_request_version, capabilities.run_request_versions),
        (
            "policy_snapshot",
            requirement.policy_snapshot_version,
            capabilities.policy_snapshot_versions,
        ),
        ("run_result", requirement.run_result_version, capabilities.run_result_versions),
    ]
    unsupported_contracts = [
        f"{name}={version}"
        for name, version, supported in contract_mismatches
        if version not in supported
    ]
    if missing or unsupported_contracts:
        details = [f"missing features: {', '.join(missing)}"] if missing else []
        if unsupported_contracts:
            details.append(f"unsupported contracts: {', '.join(unsupported_contracts)}")
        raise CapabilityNegotiationError("; ".join(details))
    return NegotiatedCapabilities(capabilities, requirement)


@dataclass(frozen=True)
class PolicySnapshot:
    """Pinned policy metadata consumed by the future native engine."""

    binding: PolicyBinding
    source_ref: str
    source_digest: str
    cache: PolicyCacheEntry
    session_id: str
    trust_domain: str
    commissioned: bool
    sinks: tuple[SinkPolicy, ...]
    capture_commitment: CaptureCommitment
    capture_durability: CaptureDurability
    capture_required: bool
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _non_empty(self.source_ref, "policy source ref")
        _digest(self.source_digest, "policy source digest")
        _non_empty(self.session_id, "session id")
        if self.trust_domain not in {"trusted-local", "restricted", "export", "metadata-only"}:
            raise ControlContractError("unsupported policy trust domain")
        if self.trust_domain == "trusted-local" and not self.commissioned:
            raise ControlContractError("trusted-local snapshots must be commissioned")
        if not self.sinks or not all(isinstance(sink, SinkPolicy) for sink in self.sinks):
            raise ControlContractError("policy snapshot must define at least one valid sink")
        if len({sink.name for sink in self.sinks}) != len(self.sinks):
            raise ControlContractError("policy snapshot sink names must be unique")
        if type(self.commissioned) is not bool:
            raise ControlContractError("commissioned must be a boolean")
        if type(self.capture_required) is not bool:
            raise ControlContractError("capture_required must be a boolean")
        if self.capture_commitment in {
            CaptureCommitment.MEMORY_ONLY,
            CaptureCommitment.PROCESS_LOCAL,
        }:
            if self.capture_durability is not CaptureDurability.NONE:
                raise ControlContractError("ephemeral capture must have none durability")
        elif self.capture_commitment is CaptureCommitment.HOST_PERSISTENT:
            if self.capture_durability is not CaptureDurability.HOST:
                raise ControlContractError("host-persistent capture must have host durability")
        elif self.capture_durability not in {
            CaptureDurability.REPLICA,
            CaptureDurability.AUTHORITATIVE,
        }:
            raise ControlContractError("replicated capture must have replica durability")
        if self.capture_required and self.capture_commitment in {
            CaptureCommitment.MEMORY_ONLY,
            CaptureCommitment.PROCESS_LOCAL,
        }:
            raise ControlContractError("required capture must survive the process")
        allowed_sink_domains = {
            "trusted-local": {"trusted-local", "restricted", "export", "metadata-only"},
            "restricted": {"restricted", "export", "metadata-only"},
            "export": {"export", "metadata-only"},
            "metadata-only": {"metadata-only"},
        }[self.trust_domain]
        if any(sink.trust_domain not in allowed_sink_domains for sink in self.sinks):
            raise ControlContractError("sink widens the commissioned session trust domain")
        if self.trust_domain == "trusted-local" and (
            not self.capture_required
            or self.capture_commitment
            not in {CaptureCommitment.HOST_PERSISTENT, CaptureCommitment.REPLICATED}
        ):
            raise ControlContractError("trusted-local snapshots require persistent capture")
        _timestamp(self.issued_at, "issued_at")
        _timestamp(self.expires_at, "expires_at")
        issued = datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if issued.tzinfo is None or expires.tzinfo is None or expires <= issued:
            raise ControlContractError("policy snapshot expiry must be after issue time")
        if self.cache.binding != self.binding:
            raise ControlContractError("policy cache entry does not bind the snapshot")

    def is_valid_at(self, now: datetime | None = None) -> bool:
        """Return whether this immutable snapshot is usable at ``now``."""
        observed = now or datetime.now(UTC)
        if observed.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return observed < expires

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "vuoro.outctl.policy-snapshot/v2",
            "snapshot_id": self.binding.snapshot_id,
            "policy_ref": self.binding.ref,
            "policy_digest": self.binding.digest,
            "source": {"ref": self.source_ref, "digest": self.source_digest},
            "cache": self.cache.to_dict(),
            "session": {
                "session_id": self.session_id,
                "trust_domain": self.trust_domain,
                "commissioned": self.commissioned,
            },
            "sinks": [sink.to_dict() for sink in self.sinks],
            "capture": {
                "commitment": self.capture_commitment.value,
                "durability": self.capture_durability.value,
                "required": self.capture_required,
            },
            "execution_authority": {
                "owner": "external-runner",
                "can_authorize_execution": False,
                "can_retry": False,
            },
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class SinkPolicy:
    """Disclosure policy for one named output sink."""

    name: str
    trust_domain: str
    disclosure: str
    redaction_required: bool
    classification_ceiling: str | None = None

    def __post_init__(self) -> None:
        _non_empty(self.name, "sink name")
        if self.name not in {"model", "runner", "audit-receipt", "handoff"}:
            raise ControlContractError("unsupported sink name")
        if type(self.redaction_required) is not bool:
            raise ControlContractError("redaction_required must be a boolean")
        if self.trust_domain not in {"trusted-local", "restricted", "export", "metadata-only"}:
            raise ControlContractError("unsupported sink trust domain")
        if self.disclosure not in {"safe-unredacted", "sanitized", "metadata-only", "deny"}:
            raise ControlContractError("unsupported sink disclosure")
        if self.disclosure == "safe-unredacted" and (
            self.trust_domain != "trusted-local" or self.redaction_required
        ):
            raise ControlContractError("safe-unredacted requires trusted-local without redaction")
        if self.disclosure == "sanitized" and not self.redaction_required:
            raise ControlContractError("sanitized sinks require redaction")
        if self.trust_domain == "metadata-only" and self.disclosure != "metadata-only":
            raise ControlContractError("metadata-only sinks require metadata-only disclosure")
        if self.trust_domain in {"restricted", "export"} and self.disclosure == "safe-unredacted":
            raise ControlContractError("restricted/export sinks cannot be safe-unredacted")
        if self.classification_ceiling is not None and self.classification_ceiling not in {
            "public",
            "internal",
            "confidential",
            "secret",
        }:
            raise ControlContractError("unsupported sink classification ceiling")

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "name": self.name,
            "trust_domain": self.trust_domain,
            "disclosure": self.disclosure,
            "redaction_required": self.redaction_required,
        }
        if self.classification_ceiling is not None:
            value["classification_ceiling"] = self.classification_ceiling
        return value
