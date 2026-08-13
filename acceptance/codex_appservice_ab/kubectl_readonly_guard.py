#!/usr/bin/env python3
"""PreToolUse guard for a read-only Kubernetes health-check arm.

The hook stores hashes and classifications only; it never logs raw commands.
It is a guardrail, not a replacement for cluster-side RBAC.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import kubectl_readonly_policy as _policy

KubectlInvocation = _policy.KubectlInvocation
classify_kubectl = _policy.classify_kubectl
identity_denial = _policy.identity_denial
_basename = _policy._basename
_classify_args = _policy._classify_args
_is_discovery_reference = _policy._is_discovery_reference
_is_secret_resource = _policy._is_secret_resource
_positionals = _policy._positionals
_shell_segments = _policy._shell_segments


def _identity_denial(command: str, pinned: str | None) -> str | None:
    return identity_denial(command, pinned, require_direct=True)


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

    invocations: list[KubectlInvocation] = (
        classify_kubectl(command) if tool_name == "Bash" else []
    )
    identity_violation = _identity_denial(command, os.environ.get("CODEX_AB_KUBECTL_PIN"))
    denial = identity_violation or next(
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
