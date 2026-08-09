"""Runner-owned, direct-argv Kubernetes read boundary.

This module deliberately accepts logical kubectl arguments rather than shell
text.  The embedding runner owns executable and cluster identity injection;
outctl owns only capture/projection mechanics around the resulting argv.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from outctl.adapter import AdapterIdentity, AdapterMode, AdapterRequest, AdapterResult, run_adapter
from outctl.projection import ProjectionLimits

_IDENTITY_FLAGS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "--cluster",
        "--user",
        "--server",
        "--token",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--tls-server-name",
    }
)
_VALUE_FLAGS = frozenset(
    {
        "-n",
        "--namespace",
        "-o",
        "--output",
        "--selector",
        "-l",
        "--field-selector",
        "--sort-by",
        "--since",
        "--since-time",
        "--tail",
        "--limit",
        "--request-timeout",
    }
)
_SIMPLE_READ_ONLY = frozenset({"api-resources", "api-versions", "version", "explain", "top"})
_MUTATING_OR_INTERACTIVE = frozenset(
    {
        "apply",
        "attach",
        "autoscale",
        "cp",
        "create",
        "debug",
        "delete",
        "drain",
        "edit",
        "exec",
        "expose",
        "label",
        "patch",
        "port-forward",
        "proxy",
        "replace",
        "rollout restart",
        "run",
        "scale",
        "set",
        "taint",
        "uncordon",
    }
)


class KubernetesReadError(ValueError):
    """Raised before execution when logical argv is outside the read boundary."""


@dataclass(frozen=True)
class KubernetesIdentity:
    executable: Path
    kubeconfig: Path
    context: str
    api_server_sha256: str

    def __post_init__(self) -> None:
        executable = self.executable.resolve()
        kubeconfig = self.kubeconfig.resolve()
        if not executable.is_file() or not kubeconfig.is_file():
            raise KubernetesReadError("pinned executable and kubeconfig must be regular files")
        if not self.context:
            raise KubernetesReadError("pinned context must not be empty")
        if len(self.api_server_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.api_server_sha256
        ):
            raise KubernetesReadError("api_server_sha256 must be lowercase SHA-256 hex")
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "kubeconfig", kubeconfig)


@dataclass(frozen=True)
class KubernetesExecutionReceipt:
    logical_command_id: str
    executable_sha256: str
    kubeconfig_sha256: str
    context_sha256: str
    api_server_sha256: str
    argv_sha256: str
    identity_binding_sha256: str
    identity_source: str = "runner_injected"
    direct_argv: bool = True

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "logical_command_id": self.logical_command_id,
            "executable_sha256": self.executable_sha256,
            "kubeconfig_sha256": self.kubeconfig_sha256,
            "context_sha256": self.context_sha256,
            "api_server_sha256": self.api_server_sha256,
            "argv_sha256": self.argv_sha256,
            "identity_binding_sha256": self.identity_binding_sha256,
            "identity_source": self.identity_source,
            "direct_argv": self.direct_argv,
        }


@dataclass(frozen=True)
class KubernetesReadResult:
    execution: AdapterResult
    receipt: KubernetesExecutionReceipt


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: object) -> str:
    return _sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _positionals(args: Sequence[str]) -> list[str]:
    result: list[str] = []
    skip = False
    for token in args:
        if skip:
            skip = False
            continue
        if token == "--":
            continue
        if token in _VALUE_FLAGS:
            skip = True
            continue
        if any(token.startswith(flag + "=") for flag in _VALUE_FLAGS if flag.startswith("--")):
            continue
        if token.startswith("-"):
            continue
        result.append(token)
    return result


def validate_kubectl_read_args(args: Sequence[str]) -> tuple[str, ...]:
    """Validate a logical kubectl argv vector without parsing shell text."""
    if isinstance(args, (str, bytes)) or not args:
        raise KubernetesReadError("kubectl read args must be a non-empty string sequence")
    values = tuple(args)
    if any(not isinstance(item, str) or not item or "\x00" in item for item in values):
        raise KubernetesReadError("kubectl read args contain an invalid argument")
    for index, token in enumerate(values):
        name = token.split("=", 1)[0]
        if name in _IDENTITY_FLAGS:
            raise KubernetesReadError("kubectl identity flags are runner-owned")
        if token == "--raw" or token.startswith("--raw="):
            raise KubernetesReadError("kubectl --raw is outside the read boundary")
        if token == "--" and index + 1 < len(values):
            raise KubernetesReadError("trailing command argv is outside the read boundary")
    positionals = _positionals(values)
    if not positionals:
        raise KubernetesReadError("kubectl verb is missing")
    verb = positionals[0].casefold()
    subverb = positionals[1].casefold() if len(positionals) > 1 else None
    resource = positionals[1].casefold() if len(positionals) > 1 else None
    combined = f"{verb} {subverb}" if subverb else verb
    if verb in _MUTATING_OR_INTERACTIVE or combined in _MUTATING_OR_INTERACTIVE:
        raise KubernetesReadError(f"kubectl {combined} is not read-only")
    if verb in {"get", "describe", "logs"}:
        if resource and any(
            item.split("/", 1)[0].split(".", 1)[0] in {"secret", "secrets"}
            for item in resource.split(",")
        ):
            raise KubernetesReadError("Kubernetes Secret reads are outside the boundary")
        return values
    if verb in _SIMPLE_READ_ONLY:
        return values
    if verb == "auth" and subverb == "can-i":
        return values
    if verb == "config" and subverb in {"current-context", "get-contexts", "view"}:
        return values
    if verb == "cluster-info" and subverb != "dump":
        return values
    if verb == "rollout" and subverb in {"status", "history"}:
        return values
    raise KubernetesReadError(f"kubectl verb {verb!r} is not in the read-only allowlist")


def build_kubernetes_receipt(
    logical_command_id: str, identity: KubernetesIdentity, args: Sequence[str]
) -> tuple[tuple[str, ...], KubernetesExecutionReceipt]:
    if not logical_command_id:
        raise KubernetesReadError("logical_command_id must not be empty")
    logical_args = validate_kubectl_read_args(args)
    argv = (
        str(identity.executable),
        "--kubeconfig",
        str(identity.kubeconfig),
        "--context",
        identity.context,
        *logical_args,
    )
    executable_sha256 = _sha256_file(identity.executable)
    kubeconfig_sha256 = _sha256_file(identity.kubeconfig)
    context_sha256 = _sha256_bytes(identity.context.encode())
    argv_sha256 = _canonical_digest(list(argv))
    binding = _canonical_digest(
        {
            "executable_sha256": executable_sha256,
            "kubeconfig_sha256": kubeconfig_sha256,
            "context_sha256": context_sha256,
            "api_server_sha256": identity.api_server_sha256,
            "argv_sha256": argv_sha256,
        }
    )
    return argv, KubernetesExecutionReceipt(
        logical_command_id=logical_command_id,
        executable_sha256=executable_sha256,
        kubeconfig_sha256=kubeconfig_sha256,
        context_sha256=context_sha256,
        api_server_sha256=identity.api_server_sha256,
        argv_sha256=argv_sha256,
        identity_binding_sha256=binding,
    )


async def run_kubernetes_read(
    *,
    logical_command_id: str,
    args: Sequence[str],
    cluster_identity: KubernetesIdentity,
    mode: AdapterMode,
    adapter_identity: AdapterIdentity,
    policy_ref: str,
    policy_digest: str,
    spool_root: Path | None = None,
    cwd: Path | None = None,
    bindings: Mapping[str, str | None] | None = None,
    projection_limits: ProjectionLimits | None = None,
) -> KubernetesReadResult:
    argv, receipt = build_kubernetes_receipt(logical_command_id, cluster_identity, args)
    request = AdapterRequest(
        mode=mode,
        argv=argv,
        policy_ref=policy_ref,
        policy_digest=policy_digest,
        identity=adapter_identity,
        bindings={**(bindings or {}), "logical_command_id": logical_command_id},
        spool_root=spool_root,
        cwd=cwd,
        projection_limits=projection_limits or ProjectionLimits(65_536, 2_000, 16_000),
    )
    return KubernetesReadResult(await run_adapter(request), receipt)

