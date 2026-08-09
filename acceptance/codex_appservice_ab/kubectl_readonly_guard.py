#!/usr/bin/env python3
"""Codex PreToolUse guard for a read-only Kubernetes health-check arm.

The hook stores hashes and classifications only; it never logs raw commands.
It is an experiment guardrail, not a replacement for cluster-side RBAC.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class KubectlInvocation:
    verb: str | None
    subverb: str | None
    resource: str | None
    read_only: bool
    denial_reason: str | None


_VALUE_FLAGS = {
    "-n",
    "--namespace",
    "--context",
    "--cluster",
    "--user",
    "--kubeconfig",
    "--server",
    "--token",
    "--request-timeout",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--tls-server-name",
    "--as",
    "--as-group",
    "-v",
    "--v",
    "-o",
    "--output",
    "-l",
    "--selector",
    "--field-selector",
    "--sort-by",
    "--chunk-size",
    "--since",
    "--since-time",
    "--tail",
    "--limit-bytes",
    "--container",
    "-c",
}

_SIMPLE_READ_ONLY = {
    "get",
    "describe",
    "logs",
    "top",
    "events",
    "version",
    "api-resources",
    "api-versions",
    "explain",
    "wait",
}

_MUTATING_OR_INTERACTIVE = {
    "apply",
    "create",
    "delete",
    "patch",
    "edit",
    "replace",
    "scale",
    "autoscale",
    "set",
    "label",
    "annotate",
    "taint",
    "cordon",
    "uncordon",
    "drain",
    "run",
    "expose",
    "exec",
    "attach",
    "cp",
    "debug",
    "port-forward",
    "proxy",
    "certificate",
}


def _basename(token: str) -> str:
    return Path(token).name


def _shell_segments(command: str, *, depth: int = 0) -> Iterable[list[str]]:
    if depth > 2:
        return
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return

    segment: list[str] = []
    for token in tokens + [";"]:
        if token and all(char in ";&|" for char in token):
            if segment:
                shell = _basename(segment[0])
                if shell in {"bash", "sh", "zsh", "dash"}:
                    for index, value in enumerate(segment[1:], start=1):
                        if value in {"-c", "-lc", "-cl"} and index + 1 < len(segment):
                            yield from _shell_segments(segment[index + 1], depth=depth + 1)
                            break
                    else:
                        yield segment
                else:
                    yield segment
            segment = []
        else:
            segment.append(token)


def _is_discovery_reference(segment: list[str], index: int) -> bool:
    """Ignore executable discovery text that does not execute kubectl."""

    prefix = segment[:index]
    for probe_index, value in enumerate(prefix):
        probe = _basename(value).casefold()
        suffix = prefix[probe_index + 1 :]
        if probe == "command" and any(flag in suffix for flag in ("-v", "-V")):
            return True
        if probe in {"type", "which", "whereis"}:
            return True
    return False


def _identity_denial(command: str, pinned: str | None) -> str | None:
    for segment in _shell_segments(command):
        for index, token in enumerate(segment):
            if _basename(token) != "kubectl" or _is_discovery_reference(segment, index):
                continue
            if index != 0:
                return (
                    "kubectl must be invoked directly so the experiment identity pin "
                    "cannot be replaced by an environment wrapper"
                )
            if "/" in token and (pinned is None or Path(token).resolve() != Path(pinned).resolve()):
                return "absolute kubectl paths cannot bypass the experiment identity pin"
            args = segment[index + 1 :]
            for flag in (
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
            ):
                if flag in args or any(value.startswith(flag + "=") for value in args):
                    return "kubectl identity override flags are not permitted"
    return None


def _positionals(tokens: list[str]) -> list[str]:
    result: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token == "--":
            continue
        if token in _VALUE_FLAGS:
            skip_next = True
            continue
        if any(token.startswith(flag + "=") for flag in _VALUE_FLAGS if flag.startswith("--")):
            continue
        if token.startswith("-"):
            continue
        result.append(token)
    return result


def _is_secret_resource(resource: str | None) -> bool:
    if not resource:
        return False
    for item in resource.casefold().split(","):
        base = item.split("/", 1)[0].split(".", 1)[0]
        if base in {"secret", "secrets"}:
            return True
    return False


def _classify_args(args: list[str]) -> KubectlInvocation:
    positionals = _positionals(args)
    verb = positionals[0].casefold() if positionals else None
    subverb = positionals[1].casefold() if len(positionals) > 1 else None
    resource = positionals[1] if len(positionals) > 1 else None

    if "--raw" in args or any(token.startswith("--raw=") for token in args):
        return KubectlInvocation(
            verb, subverb, resource, False, "kubectl --raw is outside this health-check scope"
        )
    if verb is None:
        return KubectlInvocation(None, None, None, False, "could not identify kubectl verb")
    if verb in _MUTATING_OR_INTERACTIVE:
        return KubectlInvocation(verb, subverb, resource, False, f"kubectl {verb} is not read-only")
    if verb in {"get", "describe"}:
        if _is_secret_resource(resource):
            return KubectlInvocation(
                verb,
                subverb,
                resource,
                False,
                "reading Kubernetes Secret objects is outside this experiment",
            )
        return KubectlInvocation(verb, subverb, resource, True, None)
    if verb in _SIMPLE_READ_ONLY:
        return KubectlInvocation(verb, subverb, resource, True, None)
    if verb == "cluster-info":
        allowed = subverb not in {"dump"}
        return KubectlInvocation(
            verb,
            subverb,
            resource,
            allowed,
            None if allowed else "kubectl cluster-info dump is too broad for this experiment",
        )
    if verb == "auth":
        allowed = subverb == "can-i"
        return KubectlInvocation(
            verb,
            subverb,
            resource,
            allowed,
            None if allowed else "only kubectl auth can-i is permitted",
        )
    if verb == "config":
        allowed = subverb in {"current-context", "get-contexts", "view"}
        return KubectlInvocation(
            verb,
            subverb,
            resource,
            allowed,
            None if allowed else "only read-only kubectl config inspection is permitted",
        )
    if verb == "rollout":
        allowed = subverb in {"status", "history"}
        return KubectlInvocation(
            verb,
            subverb,
            resource,
            allowed,
            None if allowed else "only kubectl rollout status/history is permitted",
        )
    return KubectlInvocation(
        verb,
        subverb,
        resource,
        False,
        f"kubectl verb {verb!r} is not in the experiment read-only allowlist",
    )


def classify_kubectl(command: str) -> list[KubectlInvocation]:
    invocations: list[KubectlInvocation] = []
    for segment in _shell_segments(command):
        for index, token in enumerate(segment):
            if _basename(token) == "kubectl" and not _is_discovery_reference(segment, index):
                invocations.append(_classify_args(segment[index + 1 :]))
    return invocations


def _append_log(payload: dict[str, Any]) -> None:
    target = os.environ.get("CODEX_AB_HOOK_LOG")
    if not target:
        return
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> int:
    try:
        hook_input = json.load(sys.stdin)
    except Exception as exc:
        print(json.dumps(_deny(f"kubectl experiment guard failed to initialize: {exc}")))
        return 0

    tool_name = hook_input.get("tool_name")
    command = ""
    tool_input = hook_input.get("tool_input")
    if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
        command = tool_input["command"]

    invocations = classify_kubectl(command) if tool_name == "Bash" else []
    identity_denial = _identity_denial(command, os.environ.get("CODEX_AB_KUBECTL_PIN"))
    denial = identity_denial or next(
        (
            item.denial_reason or "non-read-only kubectl command denied"
            for item in invocations
            if not item.read_only
        ),
        None,
    )
    _append_log(
        {
            "ts": datetime.now(UTC).isoformat(),
            "arm": os.environ.get("CODEX_AB_ARM"),
            "session_id": hook_input.get("session_id"),
            "turn_id": hook_input.get("turn_id"),
            "model": hook_input.get("model"),
            "tool_name": tool_name,
            "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()
            if command
            else None,
            "kubectl_invocations": [asdict(item) for item in invocations],
            "denied": denial is not None,
            "denial_class": (
                "cluster_identity"
                if denial and "identity" in denial
                else "read_only_policy"
                if denial
                else None
            ),
        }
    )
    if denial:
        print(json.dumps(_deny(denial)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
