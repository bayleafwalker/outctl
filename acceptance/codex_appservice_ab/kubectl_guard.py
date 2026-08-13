#!/usr/bin/env python3
"""PreToolUse guard for the bounded-output arm of the appservice pilot.

The shared read-only policy owns command parsing and classification.  This
entrypoint owns the arm's wrapper requirement and its arm-specific telemetry.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import kubectl_readonly_policy as _policy

classify_args = _policy.classify_args
identity_denial = _policy.identity_denial
iter_kubectl_tokens = _policy.iter_kubectl_tokens
_basename = _policy._basename
_is_discovery_reference = _policy._is_discovery_reference
_is_secret_resource = _policy._is_secret_resource
_positionals = _policy._positionals
_shell_segments = _policy._shell_segments


@dataclass(frozen=True)
class KubectlInvocation:
    wrapped_by_outctl: bool
    verb: str | None
    subverb: str | None
    resource: str | None
    read_only: bool
    denial_reason: str | None


def _identity_denial(command: str, pinned: str | None) -> str | None:
    return identity_denial(command, pinned)


def _is_outctl_wrapper(prefix: list[str]) -> bool:
    for index, value in enumerate(prefix):
        if Path(value).name != "outctl":
            continue
        suffix = prefix[index + 1 :]
        if suffix[:1] == ["run"] and "--" in suffix[1:]:
            return True
    for index, value in enumerate(prefix):
        if Path(value).name != "outctl_kubectl_router.py":
            continue
        suffix = prefix[index + 1 :]
        if suffix[:1] == ["run"] and "--" in suffix[1:]:
            return True
    for index, value in enumerate(prefix):
        if Path(value).name != "outctl-health":
            continue
        if not prefix[index + 1 :]:
            return True
    return False


def _classify_args(args: list[str], wrapped: bool) -> KubectlInvocation:
    item = classify_args(args)
    return KubectlInvocation(
        wrapped,
        item.verb,
        item.subverb,
        item.resource,
        item.read_only,
        item.denial_reason,
    )


def classify_kubectl(command: str) -> list[KubectlInvocation]:
    invocations: list[KubectlInvocation] = []
    for segment, index in iter_kubectl_tokens(command):
        invocations.append(
            _classify_args(segment[index + 1 :], _is_outctl_wrapper(segment[:index]))
        )
    return invocations


def _load_policy() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "outctl-routing-policy.json"
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("outctl-routing-policy.json must contain an object")
    return value


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
        policy = _load_policy()
    except Exception as exc:  # fail closed for experiment safety
        print(json.dumps(_deny(f"kubectl experiment guard failed to initialize: {exc}")))
        return 0

    tool_name = hook_input.get("tool_name")
    command = ""
    tool_input = hook_input.get("tool_input")
    if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
        command = tool_input["command"]

    invocations = classify_kubectl(command) if tool_name == "Bash" else []
    require_outctl = bool(policy.get("require_outctl", False))
    wrapper_hint = str(policy.get("wrapper_hint", "outctl run -- ..."))

    denial: str | None = None
    identity_violation = _identity_denial(command, os.environ.get("CODEX_AB_KUBECTL_PIN"))
    if identity_violation:
        denial = identity_violation
    for invocation in invocations:
        if denial:
            break
        if not invocation.read_only:
            denial = invocation.denial_reason or "non-read-only kubectl command denied"
            break
        if require_outctl and not invocation.wrapped_by_outctl:
            denial = (
                "This A/B arm requires every kubectl invocation through outctl. "
                f"Use the experiment skill and the canonical prefix: {wrapper_hint} kubectl ..."
            )
            break

    _append_log(
        {
            "ts": datetime.now(UTC).isoformat(),
            "arm": policy.get("arm"),
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
                else "require_outctl"
                if denial and "requires every kubectl" in denial
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
