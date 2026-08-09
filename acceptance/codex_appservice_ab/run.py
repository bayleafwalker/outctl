#!/usr/bin/env python3
"""Run a controlled concurrent Codex A/B pilot for outctl on appservice.

Arm A receives minimal native guidance plus a PreToolUse guard requiring every
read-only kubectl invocation through outctl. Arm B receives the same baseline
repository, prompt, model, safety guard, and runtime settings, but no outctl
guidance or requirement.

The public report contains usage/cost metrics and hashes only. Raw Codex JSONL,
stderr, and final health reports remain under the run's private/ directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from kubectl_guard import classify_kubectl

RATE_DATE = "2026-08-08"
TERRA_MODEL_ALIASES = {"gpt-5.6-terra", "terra"}
TERRA_CODEX_CREDITS_PER_M = {
    "uncached_read_input": 50.0,
    "cached_input": 5.0,
    "cache_write_input": 0.0,
    "output": 300.0,
}
TERRA_API_USD_PER_M = {
    "uncached_read_input": 2.0,
    "cached_input": 0.2,
    "cache_write_input": 2.5,
    "output": 12.0,
}
LONG_CONTEXT_THRESHOLD = 272_000
START_BARRIER_TIMEOUT_SECONDS = 15
REQUIRED_COVERAGE_AREAS = frozenset(
    ("cluster_api", "nodes", "workloads", "gitops", "storage", "events")
)
PERMISSION_PROFILE_NAME = "outctl-ab-readonly"


class ExperimentError(RuntimeError):
    """Raised for a controlled experiment setup or telemetry failure."""


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    cached_input_tokens: int
    cache_write_input_tokens: int | None
    output_tokens: int
    reasoning_output_tokens: int
    turn_completed_events: int

    @property
    def noncached_input_tokens(self) -> int:
        return self.input_tokens - self.cached_input_tokens

    @property
    def uncached_read_input_tokens(self) -> int | None:
        if self.cache_write_input_tokens is None:
            return None
        return self.noncached_input_tokens - self.cache_write_input_tokens

    @property
    def cache_hit_ratio(self) -> float | None:
        if self.input_tokens == 0:
            return None
        return self.cached_input_tokens / self.input_tokens

    @property
    def cache_write_ratio(self) -> float | None:
        if self.input_tokens == 0 or self.cache_write_input_tokens is None:
            return None
        return self.cache_write_input_tokens / self.input_tokens

    @property
    def uncached_read_ratio(self) -> float | None:
        value = self.uncached_read_input_tokens
        if self.input_tokens == 0 or value is None:
            return None
        return value / self.input_tokens

    def validate(self) -> list[str]:
        warnings: list[str] = []
        values = {
            "input_tokens": self.input_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_output_tokens": self.reasoning_output_tokens,
        }
        if self.cache_write_input_tokens is not None:
            values["cache_write_input_tokens"] = self.cache_write_input_tokens
        for name, value in values.items():
            if value < 0:
                raise ExperimentError(f"negative Codex usage field: {name}={value}")
        if self.cached_input_tokens > self.input_tokens:
            raise ExperimentError("cached_input_tokens exceeds input_tokens")
        if (
            self.cache_write_input_tokens is not None
            and self.cache_write_input_tokens > self.noncached_input_tokens
        ):
            raise ExperimentError("cache_write_input_tokens exceeds non-cached input token count")
        if self.reasoning_output_tokens > self.output_tokens:
            warnings.append(
                "reasoning_output_tokens exceeds output_tokens; local Codex semantics "
                "may have changed"
            )
        if self.turn_completed_events != 1:
            warnings.append(
                f"expected one turn.completed event, observed {self.turn_completed_events}; "
                "the final cumulative usage event was used"
            )
        return warnings


@dataclass(frozen=True)
class ProcessResult:
    arm: str
    return_code: int
    timed_out: bool
    duration_ms: int
    launched_monotonic_ns: int
    events_path: Path
    stderr_path: Path
    final_path: Path
    hook_log_path: Path
    outctl_spool_root: Path | None


@dataclass(frozen=True)
class CostRange:
    minimum: float
    maximum: float
    exact: bool
    note: str

    def to_dict(self) -> dict[str, Any]:
        point = self.minimum if self.exact else None
        return {
            "value": point,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "exact": self.exact,
            "note": self.note,
        }


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(argv),
        cwd=cwd,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise ExperimentError(
            f"command failed ({result.returncode}): {shlex.join(argv)}\n"
            f"stdout: {result.stdout.decode(errors='replace')[-2000:]}\n"
            f"stderr: {result.stderr.decode(errors='replace')[-2000:]}"
        )
    return result


def _git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    return _run(["git", "-C", str(repo), *args], input_bytes=input_bytes).stdout


def _toml_string(value: str) -> str:
    # JSON basic strings are valid TOML basic strings for these path/model values.
    return json.dumps(value)


def _validate_policy_digest(value: str) -> None:
    if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value):
        raise ExperimentError("--policy-digest must be sha256:<64 hex characters>")


def _kubectl_output(
    kubectl_bin: str,
    kubeconfig: Path,
    context: str,
    *args: str,
) -> subprocess.CompletedProcess[bytes]:
    """Run a metadata-only launcher preflight with the explicit credential."""
    env = os.environ.copy()
    env["KUBECONFIG"] = str(kubeconfig)
    env.pop("KUBECTL_PLUGINS_CALLER", None)
    return subprocess.run(
        [kubectl_bin, "--kubeconfig", str(kubeconfig), "--context", context, *args],
        env=env,
        capture_output=True,
        check=False,
    )


def _preflight_readonly_kubeconfig(
    *, kubectl_bin: str, kubeconfig: Path, context: str
) -> dict[str, Any]:
    """Verify the exact, minimum corpus permissions before model execution.

    Do not retain command output: Kubernetes responses can include operator
    context.  The public report contains only booleans and a context digest.
    """
    current = _kubectl_output(kubectl_bin, kubeconfig, context, "config", "current-context")
    current_context = current.stdout.decode("utf-8", errors="replace").strip()
    if current.returncode != 0 or current_context != context:
        raise ExperimentError("explicit kubeconfig/context validation failed")

    server = _kubectl_output(
        kubectl_bin,
        kubeconfig,
        context,
        "config",
        "view",
        "--minify",
        "-o",
        "jsonpath={.clusters[0].cluster.server}",
    )
    parsed_server = urlparse(server.stdout.decode("utf-8", errors="replace").strip())
    if server.returncode != 0 or not parsed_server.hostname:
        raise ExperimentError("explicit kubeconfig does not expose a valid API endpoint")

    allow_checks = (
        ("get", "nodes", None, None),
        ("list", "pods", None, "--all-namespaces"),
        ("list", "deployments", "gatus", None),
        ("list", "events", "gatus", None),
        ("list", "persistentvolumeclaims", "gatus", None),
    )
    deny_checks = (
        ("create", "pods", "gatus", None),
        ("delete", "deployments", "gatus", None),
        ("get", "secrets", "gatus", None),
        ("create", "pods/exec", "gatus", None),
        ("create", "pods/portforward", "gatus", None),
        ("create", "pods/ephemeralcontainers", "gatus", None),
    )

    def can_i(verb: str, resource: str, namespace: str | None, scope: str | None) -> bool:
        args = ["auth", "can-i", verb, resource]
        if namespace is not None:
            args.extend(("--namespace", namespace))
        if scope is not None:
            args.append(scope)
        result = _kubectl_output(kubectl_bin, kubeconfig, context, *args)
        answer = result.stdout.decode("utf-8", errors="replace").strip()
        return result.returncode == 0 and answer == "yes"

    allowed = [can_i(*check) for check in allow_checks]
    denied = [not can_i(*check) for check in deny_checks]
    if not all(allowed):
        raise ExperimentError("read-only kubeconfig lacks a required fixed-corpus permission")
    if not all(denied):
        raise ExperimentError(
            "read-only kubeconfig has prohibited mutation or sensitive-read authority"
        )
    return {
        "context_sha256": _sha256_text(context),
        "api_host_sha256": _sha256_text(parsed_server.hostname),
        "required_permissions_verified": len(allowed),
        "prohibited_permissions_denied": len(denied),
        # Kept private to the launch config; the public report only has its digest.
        "_api_host": parsed_server.hostname,
    }


def _run_shared_health_checker(
    *,
    launcher: Sequence[str],
    checker: Path,
    cwd: Path,
    kubeconfig: Path,
    spool_root: Path,
    policy_ref: str,
    policy_digest: str,
) -> tuple[str, dict[str, Any]]:
    """Run the appservice checker once and return only its bounded projection."""
    env = os.environ.copy()
    env["KUBECONFIG"] = str(kubeconfig)
    # The scoped identity deliberately has no Talos authority.
    env.pop("TALOSCONFIG", None)
    command = [
        *launcher,
        "run",
        "--mode",
        "enforce",
        "--spool-root",
        str(spool_root),
        "--policy-ref",
        policy_ref,
        "--policy-digest",
        policy_digest,
        "--cwd",
        str(cwd),
        "--",
        "bash",
        str(checker),
    ]
    result = subprocess.run(command, env=env, capture_output=True, check=False)
    if result.returncode != 0:
        raise ExperimentError("shared appservice health checker did not complete")
    try:
        value = json.loads(result.stdout)
        envelope = value.get("envelope") if isinstance(value, Mapping) else None
        projection = envelope.get("projection") if isinstance(envelope, Mapping) else None
        text = projection.get("inline_text") if isinstance(projection, Mapping) else None
        receipt = value.get("receipt") if isinstance(value, Mapping) else None
        if not isinstance(text, str) or not isinstance(receipt, Mapping):
            raise ValueError("bounded projection or receipt is missing")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExperimentError("shared health checker returned an invalid bounded receipt") from exc
    return text, {
        "capture_id": receipt.get("capture_id"),
        "projection_sha256": _sha256_text(text),
        "projection_bytes": len(text.encode("utf-8")),
        "spool_root": str(spool_root),
    }


def _copy_untracked(source: Path, destination: Path) -> int:
    raw = _git(source, "ls-files", "--others", "--exclude-standard", "-z")
    paths = [item for item in raw.decode("utf-8").split("\0") if item]
    for relative in paths:
        src = source / relative
        dst = destination / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            dst.symlink_to(os.readlink(src))
        elif src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True)
        else:
            shutil.copy2(src, dst)
    return len(paths)


def _prepare_worktree(
    source: Path,
    target: Path,
    commit: str,
    *,
    tracked_patch: bytes | None,
    include_untracked: bool,
) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    _git(source, "worktree", "add", "--detach", str(target), commit)
    if tracked_patch:
        _git(target, "apply", "--binary", "--whitespace=nowarn", "-", input_bytes=tracked_patch)
    return _copy_untracked(source, target) if include_untracked else 0


def _native_guidance_files(worktree: Path) -> list[Path]:
    files: list[Path] = []
    for name in ("AGENTS.md", "AGENTS.override.md"):
        path = worktree / name
        if path.is_file():
            files.append(path)
    for root in (worktree / ".agents" / "skills", worktree / ".codex"):
        if root.exists():
            files.extend(path for path in root.rglob("*") if path.is_file())
    return sorted(set(files))


def _model_guidance_files(worktree: Path) -> list[Path]:
    files: list[Path] = []
    for name in ("AGENTS.md", "AGENTS.override.md"):
        path = worktree / name
        if path.is_file():
            files.append(path)
    skills_root = worktree / ".agents" / "skills"
    if skills_root.exists():
        files.extend(path for path in skills_root.rglob("SKILL.md") if path.is_file())
    return sorted(set(files))


def _guidance_inventory(worktree: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    total_bytes = 0
    for path in _model_guidance_files(worktree):
        relative = str(path.relative_to(worktree))
        raw = path.read_bytes()
        total_bytes += len(raw)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(raw)
        digest.update(b"\0")
        entries.append(
            {
                "path": relative,
                "bytes": len(raw),
                "sha256": _sha256_bytes(raw),
            }
        )
    return {
        "files": entries,
        "file_count": len(entries),
        "bytes": total_bytes,
        "inventory_sha256": digest.hexdigest(),
    }


def _find_outctl_guidance(worktree: Path) -> list[str]:
    matches: list[str] = []
    for path in _native_guidance_files(worktree):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "outctl" in text.casefold():
            matches.append(str(path.relative_to(worktree)))
    return matches


def _append_arm_a_guidance(worktree: Path, wrapper: str, retrieval_prefix: str) -> None:
    agents = worktree / "AGENTS.md"
    existing = agents.read_text(encoding="utf-8") if agents.exists() else ""
    marker = "<!-- outctl-codex-ab-arm-a -->"
    if marker not in existing:
        addition = f"""

{marker}
## Experiment-local outctl routing

For this session's read-only appservice cluster health check, invoke every
`kubectl` command through the `outctl-kubectl-health` skill. Direct `kubectl`
is disallowed. Never inspect raw capture files or rerun a command merely to
recover omitted output.
"""
        agents.write_text(existing.rstrip() + addition + "\n", encoding="utf-8")

    skill_dir = worktree / ".agents" / "skills" / "outctl-kubectl-health"
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill = f"""---
name: outctl-kubectl-health
description: >-
  Route read-only appservice kubectl health checks through outctl with bounded
  projection and recoverable retrieval.
---

# outctl kubectl health checks

Use this skill for every `kubectl` command in the current health-check session.

Canonical execution prefix:

```bash
{wrapper} kubectl <read-only arguments>
```

Narrow retrieval example, using the capture ID returned by the Pod inventory:

```bash
{retrieval_prefix} --lines 80 <capture-id>
```

Rules:

- Use the canonical execution prefix verbatim. Do not replace it with a bare
  `outctl run`, alter its arguments, or write outside its allocated spool.
- Preserve direct argv after `--`; do not introduce an implicit shell inside outctl.
- Start from the bounded projection returned by the router. It is derived from
  `outctl run`, while raw capture bytes remain private.
- Use the router tail command against the existing capture ID only when a
  narrow omitted detail is actually needed.
- After the all-namespaces Pod inventory, perform exactly one bounded `tail`
  retrieval from that existing capture. Do not run any additional retrievals.
- Do not open raw spool files and do not rerun the original kubectl command just
  to recover more output.
- The experiment hook denies direct kubectl, mutation/interactive verbs, and
  reads of Kubernetes Secret objects.
"""
    (skill_dir / "SKILL.md").write_text(skill, encoding="utf-8")


def _router_prefixes(
    *,
    kubeconfig: Path | None,
    router: Path,
    launcher: Sequence[str],
) -> tuple[str, str]:
    """Build the exact treatment route, including its sandbox-local uv state."""

    kubeconfig_env = f"KUBECONFIG={shlex.quote(str(kubeconfig))} " if kubeconfig else ""
    router_exec = (
        f"env {kubeconfig_env}OUTCTL_ENABLED=1 OUTCTL_MODE=enforce "
        'UV_OFFLINE=1 UV_CACHE_DIR="$OUTCTL_AB_SPOOL_ROOT/uv-cache" '
        'TMPDIR="$OUTCTL_AB_SPOOL_ROOT/tmp" '
        f"python3 {shlex.quote(str(router))}"
    )
    router_common = (
        f"--outctl-command-json {shlex.quote(json.dumps(launcher, separators=(',', ':')))} "
        ' --spool-root "$OUTCTL_AB_SPOOL_ROOT"'
    )
    return router_exec, router_common


def _write_hook_config(hooks_path: Path, command: str) -> None:
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "description": "Experiment-local read-only command guard",
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "^Bash$",
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                            "timeout": 5,
                            "statusMessage": "Checking read-only kubectl policy",
                        }
                    ],
                }
            ]
        },
    }
    hooks_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _install_guard(worktree: Path, *, arm: str, wrapper: str) -> None:
    codex_dir = worktree / ".codex"
    hooks_dir = codex_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    if arm == "A":
        source_guard = Path(__file__).with_name("kubectl_guard.py")
        target_guard = hooks_dir / "kubectl_outctl_guard.py"
        shutil.copy2(source_guard, target_guard)
        policy = {
            "arm": arm,
            "require_outctl": True,
            "wrapper_hint": wrapper,
        }
        (codex_dir / "outctl-routing-policy.json").write_text(
            json.dumps(policy, indent=2) + "\n", encoding="utf-8"
        )
    else:
        # Keep the unguided baseline genuinely free of outctl-native hints. This
        # common safety hook contains no outctl vocabulary or routing behavior.
        source_guard = Path(__file__).with_name("kubectl_readonly_guard.py")
        target_guard = hooks_dir / "kubectl_readonly_guard.py"
        shutil.copy2(source_guard, target_guard)

    target_guard.chmod(0o755)
    _write_hook_config(
        codex_dir / "hooks.json",
        f'python3 "$(git rev-parse --show-toplevel)/.codex/hooks/{target_guard.name}"',
    )


def _install_home_hook(home: Path, worktree: Path, *, arm: str) -> None:
    """Register generated hooks beside the active isolated Codex config layer.

    Project-local copies remain in the detached worktree for dry-run review.
    The home-local registration is required because `codex exec --ephemeral`
    does not reliably activate a project hook file unless that project also has
    an active config layer.  The home is per arm and deleted after the run.
    """
    source_dir = worktree / ".codex" / "hooks"
    source_name = "kubectl_outctl_guard.py" if arm == "A" else "kubectl_readonly_guard.py"
    source = source_dir / source_name
    target_dir = home / "hooks"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / source_name
    shutil.copy2(source, target)
    target.chmod(0o755)
    if arm == "A":
        shutil.copy2(
            worktree / ".codex" / "outctl-routing-policy.json",
            home / "outctl-routing-policy.json",
        )
    _write_hook_config(home / "hooks.json", f"python3 {shlex.quote(str(target))}")


def _write_codex_home(
    target: Path,
    *,
    worktree: Path,
    canonical: Path,
    outctl_project: Path,
    write_roots: Sequence[Path],
    kubernetes_api_host: str | None,
    auth_source: Path | None,
    reasoning_effort: str | None,
) -> None:
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0o700)
    if auth_source is not None:
        destination = target / "auth.json"
        shutil.copy2(auth_source, destination)
        destination.chmod(0o600)

    workspace_roots = tuple(dict.fromkeys((worktree, canonical, outctl_project)))
    lines = [
        'web_search = "disabled"',
        'approval_policy = "never"',
        f"default_permissions = {_toml_string(PERMISSION_PROFILE_NAME)}",
        "",
        "[features]",
        "hooks = true",
        "memories = false",
        "external_agent_memory_import = false",
        "chronicle = false",
        "multi_agent = false",
        "multi_agent_v2 = false",
        "goals = false",
        "fast_mode = false",
        "apps = false",
        "plugins = false",
        "recommended_plugins = false",
        "standalone_web_search = false",
        "",
        f"[projects.{_toml_string(str(worktree))}]",
        'trust_level = "trusted"',
        "",
        f"[permissions.{PERMISSION_PROFILE_NAME}]",
        'description = "Experiment-local read-only appservice health-check profile"',
        'extends = ":read-only"',
        "",
        f"[permissions.{PERMISSION_PROFILE_NAME}.workspace_roots]",
        *(f"{_toml_string(str(path))} = true" for path in workspace_roots),
        "",
        f"[permissions.{PERMISSION_PROFILE_NAME}.filesystem]",
        '":minimal" = "read"',
        "",
        f"[permissions.{PERMISSION_PROFILE_NAME}.filesystem.\":workspace_roots\"]",
        '"." = "read"',
    ]
    for write_root in dict.fromkeys(write_roots):
        lines.extend(
            (
                "",
                f"[permissions.{PERMISSION_PROFILE_NAME}.filesystem.{_toml_string(str(write_root))}]",
                '"." = "write"',
            )
        )
    if kubernetes_api_host is not None:
        lines.extend(
            (
                "",
                f"[permissions.{PERMISSION_PROFILE_NAME}.network]",
                "enabled = true",
                # The API endpoint is private by design.  This does not open a
                # wildcard: the sole allow entry below remains authoritative.
                "allow_local_binding = true",
                "",
                f"[permissions.{PERMISSION_PROFILE_NAME}.network.domains]",
                f"{_toml_string(kubernetes_api_host)} = \"allow\"",
            )
        )
    if reasoning_effort:
        lines = [
            f"model_reasoning_effort = {_toml_string(reasoning_effort)}",
            "",
            *lines,
        ]
    (target / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _remove_codex_home(path: Path) -> None:
    # Homes contain copied account credentials and possibly transcripts. Never retain them.
    shutil.rmtree(path, ignore_errors=True)


def _build_codex_command(
    *,
    codex_bin: str,
    model: str,
    worktree: Path,
    schema: Path,
    final_path: Path,
    prompt: str,
    additional_write_dirs: Sequence[Path] = (),
) -> list[str]:
    command = [
        codex_bin,
        "exec",
        "--dangerously-bypass-hook-trust",
        "--ephemeral",
        "--json",
        "--model",
        model,
        "--cd",
        str(worktree),
    ]
    for directory in dict.fromkeys(additional_write_dirs):
        command.extend(("--add-dir", str(directory)))
    return [
        *command,
        "--output-schema",
        str(schema),
        "--output-last-message",
        str(final_path),
        prompt,
    ]


def _commissioning_failed(arm: Mapping[str, Any]) -> bool:
    """Identify deterministic treatment bootstrap failures before more pairs spend tokens."""

    commands = arm.get("commands") if isinstance(arm.get("commands"), Mapping) else {}
    spool = arm.get("outctl_spool") if isinstance(arm.get("outctl_spool"), Mapping) else {}
    return (
        int(commands.get("kubectl_via_outctl_attempts", 0)) > 0
        and int(commands.get("kubectl_via_outctl_completed", 0)) == 0
        and int(spool.get("capture_directory_count", 0)) == 0
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _run_arm(
    *,
    arm: str,
    command: Sequence[str],
    env: Mapping[str, str],
    output_dir: Path,
    timeout_seconds: int,
    barrier: threading.Barrier,
) -> ProcessResult:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    events_path = output_dir / "events.jsonl"
    stderr_path = output_dir / "stderr.log"
    final_path = output_dir / "final.json"
    hook_log_path = output_dir / "hook-events.jsonl"

    barrier.wait(timeout=START_BARRIER_TIMEOUT_SECONDS)
    launched = time.monotonic_ns()
    started = time.monotonic()
    timed_out = False
    with events_path.open("xb") as stdout_handle, stderr_path.open("xb") as stderr_handle:
        events_path.chmod(0o600)
        stderr_path.chmod(0o600)
        process = subprocess.Popen(
            list(command),
            env=dict(env),
            stdout=stdout_handle,
            stderr=stderr_handle,
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process)
            return_code = process.returncode if process.returncode is not None else -signal.SIGKILL
    for path in (events_path, stderr_path, final_path, hook_log_path):
        if path.exists():
            path.chmod(0o600)
    duration_ms = round((time.monotonic() - started) * 1000)
    return ProcessResult(
        arm=arm,
        return_code=return_code,
        timed_out=timed_out,
        duration_ms=duration_ms,
        launched_monotonic_ns=launched,
        events_path=events_path,
        stderr_path=stderr_path,
        final_path=final_path,
        hook_log_path=hook_log_path,
        outctl_spool_root=(
            Path(value)
            if isinstance((value := env.get("OUTCTL_AB_SPOOL_ROOT")), str) and value
            else None
        ),
    )


def _read_jsonl(
    path: Path, *, artifact: str = "events JSONL"
) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    if not path.exists():
        return events, [f"{artifact} is missing"]
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(f"invalid JSONL line {line_number}: {exc}")
                continue
            if isinstance(value, dict):
                events.append(value)
            else:
                warnings.append(f"non-object JSONL value at line {line_number}")
    return events, warnings


def _integer(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ExperimentError(f"Codex usage field {name} is not an integer: {value!r}")
    return value


def _extract_usage(events: Sequence[Mapping[str, Any]]) -> tuple[Usage | None, list[str]]:
    completed = [event for event in events if event.get("type") == "turn.completed"]
    if not completed:
        return None, ["no turn.completed usage event"]
    usage_value = completed[-1].get("usage")
    if not isinstance(usage_value, Mapping):
        return None, ["final turn.completed event has no usage object"]
    cache_write_raw = usage_value.get("cache_write_input_tokens")
    cache_write = (
        _integer(cache_write_raw, "cache_write_input_tokens")
        if cache_write_raw is not None
        else None
    )
    usage = Usage(
        input_tokens=_integer(usage_value.get("input_tokens"), "input_tokens"),
        cached_input_tokens=_integer(usage_value.get("cached_input_tokens"), "cached_input_tokens"),
        cache_write_input_tokens=cache_write,
        output_tokens=_integer(usage_value.get("output_tokens"), "output_tokens"),
        reasoning_output_tokens=_integer(
            usage_value.get("reasoning_output_tokens"), "reasoning_output_tokens"
        ),
        turn_completed_events=len(completed),
    )
    return usage, usage.validate()


def _cost_ranges(usage: Usage, *, model: str) -> dict[str, Any]:
    if model.casefold() not in TERRA_MODEL_ALIASES:
        return {
            "available": False,
            "reason": "built-in rate table is only valid for GPT-5.6 Terra",
        }

    cached = usage.cached_input_tokens
    noncached = usage.noncached_input_tokens
    output = usage.output_tokens
    cache_write = usage.cache_write_input_tokens

    if cache_write is None:
        write_min = 0
        write_max = noncached
        known = False
    else:
        write_min = write_max = cache_write
        known = True

    def codex_credits(write_tokens: int) -> float:
        read_tokens = noncached - write_tokens
        return (
            read_tokens * TERRA_CODEX_CREDITS_PER_M["uncached_read_input"]
            + cached * TERRA_CODEX_CREDITS_PER_M["cached_input"]
            + write_tokens * TERRA_CODEX_CREDITS_PER_M["cache_write_input"]
            + output * TERRA_CODEX_CREDITS_PER_M["output"]
        ) / 1_000_000

    # Cache writes are free in Codex, so more unknown writes means lower credits.
    codex_min = codex_credits(write_max)
    codex_max = codex_credits(write_min)
    codex_range = CostRange(
        minimum=codex_min,
        maximum=codex_max,
        exact=known,
        note=(
            "exact from Codex token categories"
            if known
            else "range because this CLI event omitted cache_write_input_tokens"
        ),
    )

    def api_base(write_tokens: int) -> tuple[float, float, float]:
        read_tokens = noncached - write_tokens
        input_cost = (
            read_tokens * TERRA_API_USD_PER_M["uncached_read_input"]
            + cached * TERRA_API_USD_PER_M["cached_input"]
            + write_tokens * TERRA_API_USD_PER_M["cache_write_input"]
        ) / 1_000_000
        output_cost = output * TERRA_API_USD_PER_M["output"] / 1_000_000
        return input_cost + output_cost, input_cost, output_cost

    api_low_base, input_low, output_cost = api_base(write_min)
    api_high_base, input_high, _ = api_base(write_max)
    base_min = min(api_low_base, api_high_base)
    base_max = max(api_low_base, api_high_base)

    long_context_ambiguous = usage.input_tokens > LONG_CONTEXT_THRESHOLD
    if long_context_ambiguous:
        # Aggregate turn telemetry cannot identify which underlying requests crossed
        # the per-request 272K threshold. Bound it between base pricing and the case
        # where all input receives 2x and all output receives 1.5x.
        max_input_cost = max(input_low, input_high) * 2
        max_total = max_input_cost + output_cost * 1.5
        api_range = CostRange(
            minimum=base_min,
            maximum=max(base_max, max_total),
            exact=False,
            note=(
                "aggregate input exceeded 272K; per-request long-context pricing "
                "cannot be reconstructed from turn.completed alone"
            ),
        )
    else:
        api_range = CostRange(
            minimum=base_min,
            maximum=base_max,
            exact=known,
            note=(
                "exact at standard Terra API rates"
                if known
                else "range because this CLI event omitted cache_write_input_tokens"
            ),
        )

    return {
        "available": True,
        "rate_date": RATE_DATE,
        "codex_credits": codex_range.to_dict(),
        "api_equivalent_usd": api_range.to_dict(),
        "reasoning_tokens_note": (
            "reasoning_output_tokens are included in output_tokens and are not added twice"
        ),
        "accounting_assumption": (
            "cached_input_tokens and cache_write_input_tokens are subsets of input_tokens; "
            "the parser rejects overlapping categories larger than input_tokens"
        ),
    }


def _command_metrics(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = 0
    completed = 0
    failed = 0
    declined = 0
    output_bytes = 0
    kubectl_output_bytes = 0
    command_hashes: list[str] = []
    kubectl_attempts = 0
    kubectl_completed = 0
    direct_attempts = 0
    direct_completed = 0
    wrapped_attempts = 0
    wrapped_completed = 0
    non_read_only_attempts = 0

    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, Mapping) or item.get("type") != "command_execution":
            continue
        total += 1
        command = item.get("command") if isinstance(item.get("command"), str) else ""
        command_hashes.append(_sha256_text(command))
        output = item.get("aggregated_output")
        if isinstance(output, str):
            output_bytes += len(output.encode("utf-8"))
        status = item.get("status")
        if status == "completed":
            completed += 1
        elif status == "declined":
            declined += 1
        elif status == "failed":
            failed += 1
        invocations = classify_kubectl(command)
        kubectl_attempts += len(invocations)
        if invocations and isinstance(output, str):
            kubectl_output_bytes += len(output.encode("utf-8"))
        for invocation in invocations:
            if not invocation.read_only:
                non_read_only_attempts += 1
            if invocation.wrapped_by_outctl:
                wrapped_attempts += 1
                if status == "completed":
                    wrapped_completed += 1
            else:
                direct_attempts += 1
                if status == "completed":
                    direct_completed += 1
            if status == "completed":
                kubectl_completed += 1

    return {
        "command_items": total,
        "completed": completed,
        "failed": failed,
        "declined": declined,
        "model_visible_command_output_bytes": output_bytes,
        "model_visible_kubectl_output_bytes": kubectl_output_bytes,
        "command_sha256": sorted(command_hashes),
        "kubectl_attempts": kubectl_attempts,
        "kubectl_completed": kubectl_completed,
        "kubectl_direct_attempts": direct_attempts,
        "kubectl_direct_completed": direct_completed,
        "kubectl_via_outctl_attempts": wrapped_attempts,
        "kubectl_via_outctl_completed": wrapped_completed,
        "kubectl_non_read_only_attempts": non_read_only_attempts,
    }


def _spool_metrics(root: Path | None) -> tuple[dict[str, Any], list[str]]:
    metrics: dict[str, Any] = {
        "configured": root is not None,
        "present": False,
        "capture_directory_count": 0,
        "capture_count": 0,
        "partial_capture_count": 0,
        "capture_status_counts": {},
        "retained_stdout_bytes": 0,
        "retained_stderr_bytes": 0,
        "retained_total_bytes": 0,
        "manifest_errors": 0,
        "retrieval_count": 0,
    }
    warnings: list[str] = []
    if root is None:
        return metrics, warnings

    captures_root = root / "captures"
    partial_root = root / "partial"
    metrics["present"] = root.exists()
    retrieval_events = root / "retrieval-events.jsonl"
    if retrieval_events.is_file():
        retrievals, retrieval_warnings = _read_jsonl(retrieval_events, artifact="retrieval log")
        metrics["retrieval_count"] = len(retrievals)
        warnings.extend(retrieval_warnings)
    if partial_root.is_dir():
        try:
            metrics["partial_capture_count"] = sum(
                1 for path in partial_root.iterdir() if path.is_dir()
            )
        except OSError as exc:
            warnings.append(f"could not inspect outctl partial spool: {exc}")

    if not captures_root.is_dir():
        warnings.append("configured outctl spool has no captures directory")
        return metrics, warnings

    status_counts: dict[str, int] = {}
    try:
        capture_directories = sorted(path for path in captures_root.iterdir() if path.is_dir())
    except OSError as exc:
        warnings.append(f"could not enumerate outctl captures: {exc}")
        return metrics, warnings
    metrics["capture_directory_count"] = len(capture_directories)

    for capture_directory in capture_directories:
        manifest_path = capture_directory / "manifest.json"
        if not manifest_path.is_file():
            metrics["manifest_errors"] = int(metrics["manifest_errors"]) + 1
            warnings.append(f"outctl capture {capture_directory.name} has no manifest.json")
            continue
        try:
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(value, Mapping):
                raise ValueError("manifest root is not an object")
            status = value.get("capture_status")
            status_name = status if isinstance(status, str) and status else "UNKNOWN"
            streams = value.get("streams")
            stdout = streams.get("stdout") if isinstance(streams, Mapping) else None
            stderr = streams.get("stderr") if isinstance(streams, Mapping) else None
            stdout_bytes = stdout.get("bytes") if isinstance(stdout, Mapping) else None
            stderr_bytes = stderr.get("bytes") if isinstance(stderr, Mapping) else None
            if not isinstance(stdout_bytes, int) or isinstance(stdout_bytes, bool):
                raise ValueError("stdout byte count is missing or invalid")
            if not isinstance(stderr_bytes, int) or isinstance(stderr_bytes, bool):
                raise ValueError("stderr byte count is missing or invalid")
            if stdout_bytes < 0 or stderr_bytes < 0:
                raise ValueError("stream byte count is negative")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            metrics["manifest_errors"] = int(metrics["manifest_errors"]) + 1
            warnings.append(f"invalid outctl manifest {manifest_path.parent.name}: {exc}")
            continue

        metrics["capture_count"] = int(metrics["capture_count"]) + 1
        metrics["retained_stdout_bytes"] = int(metrics["retained_stdout_bytes"]) + stdout_bytes
        metrics["retained_stderr_bytes"] = int(metrics["retained_stderr_bytes"]) + stderr_bytes
        status_counts[status_name] = status_counts.get(status_name, 0) + 1

    metrics["capture_status_counts"] = status_counts
    metrics["retained_total_bytes"] = int(metrics["retained_stdout_bytes"]) + int(
        metrics["retained_stderr_bytes"]
    )
    return metrics, warnings


def _hook_metrics(path: Path) -> tuple[dict[str, Any], list[str]]:
    events, warnings = _read_jsonl(path, artifact="hook log")
    models = sorted(
        {value for event in events if isinstance((value := event.get("model")), str) and value}
    )
    require_denials = sum(event.get("denial_class") == "require_outctl" for event in events)
    safety_denials = sum(event.get("denial_class") == "read_only_policy" for event in events)
    return (
        {
            "events": len(events),
            "denials": sum(bool(event.get("denied")) for event in events),
            "require_outctl_denials": require_denials,
            "read_only_policy_denials": safety_denials,
            "observed_models": models,
        },
        warnings,
    )


def _basic_final_validation(value: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["final result is not a JSON object"]
    required = {
        "overall_status",
        "summary",
        "coverage",
        "checks",
        "findings",
        "limitations",
        "mutations_performed",
    }
    missing = sorted(required - set(value))
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
    if value.get("overall_status") not in {"healthy", "degraded", "unknown"}:
        errors.append("invalid overall_status")
    if value.get("mutations_performed") is not False:
        errors.append("mutations_performed must be false")
    coverage = value.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != REQUIRED_COVERAGE_AREAS:
        errors.append("coverage must contain every required health area")
    for name in ("checks", "findings", "limitations"):
        if not isinstance(value.get(name), list):
            errors.append(f"{name} must be an array")
    return not errors, errors


_POD_SUFFIX = re.compile(r"-[a-z0-9]{5}$")


def _canonical_finding_subject(finding: Mapping[str, Any]) -> str:
    """Return a stable quality-comparison subject without trusting model IDs.

    The output schema intentionally leaves ``findings[].id`` model-defined.
    Comparing those labels literally turns equivalent reports into invalid A/B
    pairs when one arm emits a descriptive ID and the other emits a sequence
    number. A component is the structured subject when supplied; strip a
    Kubernetes pod's generated five-character suffix so concurrent reads of
    the same workload compare equal. Fall back to the ID for schemas lacking a
    component, keeping the comparison conservative rather than inventing a
    semantic match from prose.
    """

    component = str(finding.get("component", "")).strip().casefold()
    if component:
        namespace, separator, resource = component.partition("/")
        if separator:
            resource = _POD_SUFFIX.sub("", resource)
            return f"component:{namespace}/{resource}"
        return f"component:{_POD_SUFFIX.sub('', component)}"
    return f"id:{str(finding.get('id', '')).strip().casefold()}"


def _final_metrics(
    path: Path,
    validator: Draft202012Validator,
) -> tuple[dict[str, Any], set[tuple[str, str]], list[str]]:
    warnings: list[str] = []
    if not path.exists():
        return (
            {
                "present": False,
                "sha256": None,
                "bytes": 0,
                "schema_valid_basic": False,
                "schema_valid": False,
                "overall_status": None,
                "check_count": 0,
                "finding_count": 0,
                "limitation_count": 0,
                "quality_fingerprint": None,
            },
            set(),
            ["final output file is missing"],
        )
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return (
            {
                "present": True,
                "sha256": _sha256_bytes(raw),
                "bytes": len(raw),
                "schema_valid_basic": False,
                "schema_valid": False,
                "overall_status": None,
                "check_count": 0,
                "finding_count": 0,
                "limitation_count": 0,
                "quality_fingerprint": None,
            },
            set(),
            [f"final output is not JSON: {exc}"],
        )

    basic_valid, basic_errors = _basic_final_validation(value)
    warnings.extend(basic_errors)
    schema_errors = sorted(
        validator.iter_errors(value),
        key=lambda error: (
            tuple(str(item) for item in error.absolute_path),
            error.message,
        ),
    )
    for error in schema_errors:
        location = "/".join(str(item) for item in error.absolute_path) or "<root>"
        warnings.append(f"schema validation failed at {location}: {error.message}")
    schema_valid = not schema_errors
    checks = value.get("checks") if isinstance(value, Mapping) else []
    coverage = value.get("coverage") if isinstance(value, Mapping) else {}
    findings = value.get("findings") if isinstance(value, Mapping) else []
    limitations = value.get("limitations") if isinstance(value, Mapping) else []
    checks = checks if isinstance(checks, list) else []
    findings = findings if isinstance(findings, list) else []
    limitations = limitations if isinstance(limitations, list) else []
    coverage = coverage if isinstance(coverage, Mapping) else {}

    signature: set[tuple[str, str]] = set()
    for area, item in coverage.items():
        if isinstance(area, str) and isinstance(item, Mapping):
            status = str(item.get("status", "")).strip().casefold()
            if area in REQUIRED_COVERAGE_AREAS:
                signature.add((f"coverage:{area}", status))
    for check in checks:
        if isinstance(check, Mapping):
            area = str(check.get("area", "")).strip().casefold()
            status = str(check.get("status", "")).strip().casefold()
            if area:
                signature.add((f"check:{area}", status))
    for finding in findings:
        if isinstance(finding, Mapping):
            severity = str(finding.get("severity", "")).strip().casefold()
            subject = _canonical_finding_subject(finding)
            if subject != "id:":
                signature.add((f"finding:{subject}", severity))
    fingerprint = _sha256_text(
        json.dumps(sorted(signature), separators=(",", ":"), ensure_ascii=False)
    )
    return (
        {
            "present": True,
            "sha256": _sha256_bytes(raw),
            "bytes": len(raw),
            "schema_valid_basic": basic_valid,
            "schema_valid": schema_valid,
            "overall_status": value.get("overall_status") if isinstance(value, Mapping) else None,
            "check_count": len(checks),
            "finding_count": len(findings),
            "limitation_count": len(limitations),
            "quality_fingerprint": fingerprint,
        },
        signature,
        warnings,
    )


def _jaccard(left: set[tuple[str, str]], right: set[tuple[str, str]]) -> float | None:
    union = left | right
    if not union:
        return 1.0
    return len(left & right) / len(union)


def _usage_public(usage: Usage | None) -> dict[str, Any] | None:
    if usage is None:
        return None
    return {
        **asdict(usage),
        "noncached_input_tokens": usage.noncached_input_tokens,
        "uncached_read_input_tokens": usage.uncached_read_input_tokens,
        "cache_hit_ratio": usage.cache_hit_ratio,
        "cache_write_ratio": usage.cache_write_ratio,
        "uncached_read_ratio": usage.uncached_read_ratio,
    }


def _models_equivalent(requested: str, observed: str) -> bool:
    requested_folded = requested.casefold()
    observed_folded = observed.casefold()
    return requested_folded == observed_folded or (
        requested_folded in TERRA_MODEL_ALIASES and observed_folded in TERRA_MODEL_ALIASES
    )


def _parse_arm(
    result: ProcessResult,
    *,
    requested_model: str,
    validator: Draft202012Validator,
) -> tuple[dict[str, Any], set[tuple[str, str]]]:
    events, warnings = _read_jsonl(result.events_path)
    event_types: dict[str, int] = {}
    for event in events:
        event_type = event.get("type")
        if isinstance(event_type, str):
            event_types[event_type] = event_types.get(event_type, 0) + 1
    try:
        stderr_text = result.stderr_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        stderr_text = ""
    diagnostic_source = "\n".join(
        str(event.get("message", "")) for event in events if event.get("type") == "error"
    ) + "\n" + stderr_text
    folded_diagnostic = diagnostic_source.casefold()
    diagnostic_code = next(
        (
            code
            for code, terms in {
                "auth": ("auth", "login", "credential"),
                "model_unavailable": ("model", "unavailable", "not found"),
                "schema": ("schema", "structured output"),
                "config": ("config", "toml"),
                "provider_network": ("network", "connect", "dns"),
                "rate_limit": ("rate limit", "quota"),
                "hook_config": ("hook",),
                "sandbox": ("sandbox", "permission denied"),
            }.items()
            if any(term in folded_diagnostic for term in terms)
        ),
        "unknown" if diagnostic_source else None,
    )
    try:
        usage, usage_warnings = _extract_usage(events)
    except ExperimentError as exc:
        usage = None
        usage_warnings = [str(exc)]
    warnings.extend(usage_warnings)
    hook, hook_warnings = _hook_metrics(result.hook_log_path)
    warnings.extend(hook_warnings)
    spool, spool_warnings = _spool_metrics(result.outctl_spool_root)
    warnings.extend(spool_warnings)
    final, signature, final_warnings = _final_metrics(result.final_path, validator)
    warnings.extend(final_warnings)
    commands = _command_metrics(events)
    thread_ids = [
        event.get("thread_id")
        for event in events
        if event.get("type") == "thread.started" and isinstance(event.get("thread_id"), str)
    ]
    if commands.get("command_items", 0) and not hook.get("events", 0):
        warnings.append(
            "no PreToolUse hook telemetry was observed despite command execution; "
            "verify project hook loading/trust"
        )

    errors = [
        event.get("message")
        for event in events
        if event.get("type") == "error" and isinstance(event.get("message"), str)
    ]
    reroute_signals = [
        message
        for message in errors
        if "rerout" in message.casefold() or "fallback model" in message.casefold()
    ]
    if reroute_signals:
        warnings.append("Codex event stream contained a model reroute/fallback signal")

    observed_models = {
        str(item) for item in hook.get("observed_models", []) if isinstance(item, str)
    }
    model_mismatch = bool(observed_models) and not all(
        _models_equivalent(requested_model, observed) for observed in observed_models
    )
    if model_mismatch:
        warnings.append(
            f"hook telemetry observed models {sorted(observed_models)}, not requested "
            f"{requested_model}"
        )

    pricing = (
        _cost_ranges(usage, model=requested_model)
        if usage is not None and not model_mismatch and not reroute_signals
        else {
            "available": False,
            "reason": (
                "usage missing, active model did not match requested model, or a model "
                "reroute/fallback signal was observed"
            ),
        }
    )

    return (
        {
            "exit_code": result.return_code,
            "timed_out": result.timed_out,
            "duration_ms": result.duration_ms,
            "thread_id": thread_ids[-1] if thread_ids else None,
            "thread_started_events": len(thread_ids),
            "usage": _usage_public(usage),
            "pricing": pricing,
            "commands": commands,
            "hooks": hook,
            "outctl_spool": spool,
            "final": final,
            "event_errors": len(errors),
            "startup_diagnostics": {
                "event_type_counts": event_types,
                "stderr_bytes": len(stderr_text.encode("utf-8")),
                "stderr_lines": len(stderr_text.splitlines()),
                "code": diagnostic_code,
            },
            "model_observed": bool(observed_models),
            "model_mismatch": model_mismatch,
            "model_reroute_signal": bool(reroute_signals),
            "warnings": warnings,
            "private_artifacts": {
                "events": str(result.events_path),
                "stderr": str(result.stderr_path),
                "final": str(result.final_path),
                "hook_log": str(result.hook_log_path),
                "events_sha256": _sha256_file(result.events_path),
                "stderr_sha256": _sha256_file(result.stderr_path),
            },
        },
        signature,
    )


def _nested_number(value: Mapping[str, Any], path: Sequence[str]) -> float | None:
    current: Any = value
    for part in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    if (
        isinstance(current, (int, float))
        and not isinstance(current, bool)
        and math.isfinite(current)
    ):
        return float(current)
    return None


def _comparison_metric(
    a: Mapping[str, Any],
    b: Mapping[str, Any],
    path: Sequence[str],
) -> dict[str, Any]:
    left = _nested_number(a, path)
    right = _nested_number(b, path)
    if left is None or right is None:
        return {"a": left, "b": right, "a_minus_b": None, "reduction_pct": None}
    reduction = None if right == 0 else (right - left) / right * 100
    return {
        "a": left,
        "b": right,
        "a_minus_b": left - right,
        "reduction_pct": reduction,
    }


def _compare_pair(
    arm_a: Mapping[str, Any],
    arm_b: Mapping[str, Any],
    signature_a: set[tuple[str, str]],
    signature_b: set[tuple[str, str]],
    launch_skew_ms: float,
) -> dict[str, Any]:
    metrics = {
        "input_tokens": _comparison_metric(arm_a, arm_b, ("usage", "input_tokens")),
        "cached_input_tokens": _comparison_metric(arm_a, arm_b, ("usage", "cached_input_tokens")),
        "noncached_input_tokens": _comparison_metric(
            arm_a, arm_b, ("usage", "noncached_input_tokens")
        ),
        "uncached_read_input_tokens": _comparison_metric(
            arm_a, arm_b, ("usage", "uncached_read_input_tokens")
        ),
        "cache_write_input_tokens": _comparison_metric(
            arm_a, arm_b, ("usage", "cache_write_input_tokens")
        ),
        "output_tokens": _comparison_metric(arm_a, arm_b, ("usage", "output_tokens")),
        "reasoning_output_tokens": _comparison_metric(
            arm_a, arm_b, ("usage", "reasoning_output_tokens")
        ),
        "cache_hit_ratio": _comparison_metric(arm_a, arm_b, ("usage", "cache_hit_ratio")),
        "cache_write_ratio": _comparison_metric(arm_a, arm_b, ("usage", "cache_write_ratio")),
        "uncached_read_ratio": _comparison_metric(arm_a, arm_b, ("usage", "uncached_read_ratio")),
        "model_visible_command_output_bytes": _comparison_metric(
            arm_a, arm_b, ("commands", "model_visible_command_output_bytes")
        ),
        "model_visible_kubectl_output_bytes": _comparison_metric(
            arm_a, arm_b, ("commands", "model_visible_kubectl_output_bytes")
        ),
        "duration_ms": _comparison_metric(arm_a, arm_b, ("duration_ms",)),
        "codex_credits": _comparison_metric(arm_a, arm_b, ("pricing", "codex_credits", "value")),
        "api_equivalent_usd": _comparison_metric(
            arm_a, arm_b, ("pricing", "api_equivalent_usd", "value")
        ),
    }

    a_commands = arm_a.get("commands") if isinstance(arm_a.get("commands"), Mapping) else {}
    b_commands = arm_b.get("commands") if isinstance(arm_b.get("commands"), Mapping) else {}
    a_hooks = arm_a.get("hooks") if isinstance(arm_a.get("hooks"), Mapping) else {}
    b_hooks = arm_b.get("hooks") if isinstance(arm_b.get("hooks"), Mapping) else {}
    a_spool = arm_a.get("outctl_spool") if isinstance(arm_a.get("outctl_spool"), Mapping) else {}
    a_final = arm_a.get("final") if isinstance(arm_a.get("final"), Mapping) else {}
    b_final = arm_b.get("final") if isinstance(arm_b.get("final"), Mapping) else {}

    treatment_compliant = (
        int(a_commands.get("kubectl_completed", 0)) > 0
        and int(a_commands.get("kubectl_direct_completed", 0)) == 0
        and int(a_commands.get("kubectl_via_outctl_completed", 0))
        == int(a_commands.get("kubectl_completed", 0))
    )
    treatment_first_try_compliant = (
        treatment_compliant
        and int(a_commands.get("kubectl_direct_attempts", 0)) == 0
        and int(a_hooks.get("require_outctl_denials", 0)) == 0
    )
    treatment_capture_accounted = (
        int(a_spool.get("capture_directory_count", 0))
        == int(a_commands.get("kubectl_via_outctl_attempts", 0))
        and int(a_spool.get("capture_directory_count", 0)) > 0
        and int(a_spool.get("capture_count", 0)) == int(a_spool.get("capture_directory_count", 0))
        and int(a_spool.get("partial_capture_count", 0)) == 0
        and int(a_spool.get("manifest_errors", 0)) == 0
        and set(a_spool.get("capture_status_counts", {})) <= {"COMPLETE"}
        and int(a_spool.get("retrieval_count", 0)) == 1
    )
    hooks_observed_both_arms = (
        int(a_hooks.get("events", 0)) > 0 and int(b_hooks.get("events", 0)) > 0
    )
    baseline_spontaneously_used_outctl = int(b_commands.get("kubectl_via_outctl_completed", 0)) > 0
    no_mutation_attempts = (
        int(a_commands.get("kubectl_non_read_only_attempts", 0)) == 0
        and int(b_commands.get("kubectl_non_read_only_attempts", 0)) == 0
        and int(a_hooks.get("read_only_policy_denials", 0)) == 0
        and int(b_hooks.get("read_only_policy_denials", 0)) == 0
    )
    same_overall_status = a_final.get("overall_status") == b_final.get("overall_status")
    critical_high_a = {
        item
        for item in signature_a
        if item[0].startswith("finding:") and item[1] in {"critical", "high"}
    }
    critical_high_b = {
        item
        for item in signature_b
        if item[0].startswith("finding:") and item[1] in {"critical", "high"}
    }
    critical_high_findings_agree = critical_high_a == critical_high_b
    requested_model_integrity = (
        bool(arm_a.get("model_observed"))
        and bool(arm_b.get("model_observed"))
        and not bool(arm_a.get("model_mismatch"))
        and not bool(arm_b.get("model_mismatch"))
        and not bool(arm_a.get("model_reroute_signal"))
        and not bool(arm_b.get("model_reroute_signal"))
    )
    quality_similarity = _jaccard(signature_a, signature_b)
    raw_retained = _nested_number(arm_a, ("outctl_spool", "retained_total_bytes"))
    exposed_kubectl = _nested_number(arm_a, ("commands", "model_visible_kubectl_output_bytes"))
    outctl_exposure_ratio = (
        exposed_kubectl / raw_retained
        if raw_retained is not None and exposed_kubectl is not None and raw_retained > 0
        else None
    )

    flags: list[str] = []
    if not treatment_compliant:
        flags.append("arm A did not complete all kubectl work through outctl")
    elif not treatment_first_try_compliant:
        flags.append("arm A required hook correction before completing kubectl through outctl")
    if not treatment_capture_accounted:
        flags.append(
            "arm A did not produce one complete capture per wrapped command and one "
            "bounded retrieval"
        )
    if not hooks_observed_both_arms:
        flags.append("PreToolUse hook telemetry was not observed in both arms")
    if baseline_spontaneously_used_outctl:
        flags.append("arm B discovered/used outctl, contaminating the unguided baseline")
    if not no_mutation_attempts:
        flags.append("at least one non-read-only kubectl attempt was observed and guarded")
    if not same_overall_status:
        flags.append("arms reached different overall health statuses")
    if not critical_high_findings_agree:
        flags.append("arms disagreed on critical/high finding identifiers or classifications")
    if not requested_model_integrity:
        flags.append("requested model identity was not verified cleanly in both arms")
    if quality_similarity is not None and quality_similarity < 0.6:
        flags.append("structured health evidence overlap was below 0.60")
    if launch_skew_ms > 250:
        flags.append("process launch skew exceeded 250 ms")

    pair_valid = (
        int(arm_a.get("exit_code", -1)) == 0
        and int(arm_b.get("exit_code", -1)) == 0
        and not bool(arm_a.get("timed_out"))
        and not bool(arm_b.get("timed_out"))
        and bool(a_final.get("schema_valid"))
        and bool(b_final.get("schema_valid"))
        and treatment_compliant
        and treatment_capture_accounted
        and hooks_observed_both_arms
        and not baseline_spontaneously_used_outctl
        and no_mutation_attempts
        and same_overall_status
        and critical_high_findings_agree
        and requested_model_integrity
        and (quality_similarity is None or quality_similarity >= 0.6)
        and launch_skew_ms <= 250
    )

    return {
        "launch_skew_ms": launch_skew_ms,
        "metrics": metrics,
        "treatment_compliant": treatment_compliant,
        "treatment_first_try_compliant": treatment_first_try_compliant,
        "treatment_capture_accounted": treatment_capture_accounted,
        "hooks_observed_both_arms": hooks_observed_both_arms,
        "baseline_spontaneously_used_outctl": baseline_spontaneously_used_outctl,
        "same_overall_status": same_overall_status,
        "critical_high_findings_agree": critical_high_findings_agree,
        "requested_model_integrity": requested_model_integrity,
        "quality_signature_jaccard": quality_similarity,
        "arm_a_outctl_exposure_ratio": outctl_exposure_ratio,
        "no_non_read_only_kubectl_attempts": no_mutation_attempts,
        "pair_valid": pair_valid,
        "flags": flags,
    }


def _median(values: Iterable[float | None]) -> float | None:
    usable = [value for value in values if value is not None and math.isfinite(value)]
    return statistics.median(usable) if usable else None


def _aggregate_pairs(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    metric_names = [
        "input_tokens",
        "cached_input_tokens",
        "noncached_input_tokens",
        "uncached_read_input_tokens",
        "cache_write_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "cache_hit_ratio",
        "cache_write_ratio",
        "uncached_read_ratio",
        "model_visible_command_output_bytes",
        "model_visible_kubectl_output_bytes",
        "duration_ms",
        "codex_credits",
        "api_equivalent_usd",
    ]
    valid_pairs = [
        pair
        for pair in pairs
        if isinstance(pair.get("comparison"), Mapping)
        and bool(pair.get("comparison", {}).get("pair_valid"))
    ]
    medians: dict[str, Any] = {}
    for name in metric_names:
        values: list[float | None] = []
        for pair in valid_pairs:
            comparison = pair.get("comparison")
            if not isinstance(comparison, Mapping):
                values.append(None)
                continue
            metrics = comparison.get("metrics")
            metric = metrics.get(name) if isinstance(metrics, Mapping) else None
            value = metric.get("reduction_pct") if isinstance(metric, Mapping) else None
            values.append(float(value) if isinstance(value, (int, float)) else None)
        medians[name] = {"median_reduction_pct": _median(values)}
    return {
        "pairs": len(pairs),
        "valid_pairs": len(valid_pairs),
        "invalid_pairs": len(pairs) - len(valid_pairs),
        "all_pairs_valid": len(valid_pairs) == len(pairs),
        "all_treatment_compliant": all(
            bool(pair.get("comparison", {}).get("treatment_compliant"))
            for pair in pairs
            if isinstance(pair.get("comparison"), Mapping)
        ),
        "all_treatment_first_try_compliant": all(
            bool(pair.get("comparison", {}).get("treatment_first_try_compliant"))
            for pair in pairs
            if isinstance(pair.get("comparison"), Mapping)
        ),
        "all_treatment_captures_accounted": all(
            bool(pair.get("comparison", {}).get("treatment_capture_accounted"))
            for pair in pairs
            if isinstance(pair.get("comparison"), Mapping)
        ),
        "all_hooks_observed_both_arms": all(
            bool(pair.get("comparison", {}).get("hooks_observed_both_arms"))
            for pair in pairs
            if isinstance(pair.get("comparison"), Mapping)
        ),
        "any_baseline_outctl_use": any(
            bool(pair.get("comparison", {}).get("baseline_spontaneously_used_outctl"))
            for pair in pairs
            if isinstance(pair.get("comparison"), Mapping)
        ),
        "median_reductions": medians,
    }


def _codex_version(codex_bin: str) -> str | None:
    try:
        result = _run([codex_bin, "--version"], check=False)
    except OSError:
        return None
    text = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
    return text or None


def _write_json_private(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--appservice", type=Path, default=Path("/projects/dev/appservice"))
    parser.add_argument(
        "--canonical-appservice",
        type=Path,
        default=Path("/projects/dev/appservice"),
        help="Canonical directory whose direnv environment provides kubeconfig/access",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--kubeconfig",
        type=Path,
        default=None,
        help="Explicit read-only kubeconfig required for live runs; dry-runs need none",
    )
    parser.add_argument(
        "--context",
        default=None,
        help="Explicit context in --kubeconfig, required for live runs",
    )
    parser.add_argument("--kubectl-bin", default="kubectl")
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--model", default="gpt-5.6-terra")
    parser.add_argument("--reasoning-effort", default=None)
    parser.add_argument(
        "--health-checker",
        type=Path,
        default=None,
        help="Optional appservice read-only checker run once as shared bounded context",
    )
    parser.add_argument("--pairs", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--prompt", type=Path, default=here / "prompt.md")
    parser.add_argument(
        "--output-schema",
        type=Path,
        default=here / "health-result.codex-output.schema.json",
        help="Codex-compatible JSON Schema used to constrain the final response",
    )
    parser.add_argument("--schema", type=Path, default=here / "health-result.schema.json")
    parser.add_argument(
        "--outctl-cmd",
        default="outctl",
        help="Shell-like launcher prefix, e.g. 'uv run --project /projects/dev/outctl outctl'",
    )
    parser.add_argument("--policy-ref", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--include-untracked", action="store_true")
    parser.add_argument("--allow-contaminated-baseline", action="store_true")
    parser.add_argument("--keep-worktrees", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    _validate_policy_digest(args.policy_digest)
    if args.pairs < 1:
        raise ExperimentError("--pairs must be at least 1")
    if args.timeout_seconds < 1:
        raise ExperimentError("--timeout-seconds must be positive")

    source = args.appservice.resolve()
    canonical = args.canonical_appservice.resolve()
    kubeconfig = args.kubeconfig.resolve() if args.kubeconfig is not None else None
    prompt_path = args.prompt.resolve()
    output_schema_path = args.output_schema.resolve()
    schema_path = args.schema.resolve()
    health_checker = args.health_checker.resolve() if args.health_checker is not None else None
    for path, name in ((source, "appservice"), (canonical, "canonical appservice")):
        if not path.is_dir():
            raise ExperimentError(f"{name} directory does not exist: {path}")
    if not prompt_path.is_file() or not output_schema_path.is_file() or not schema_path.is_file():
        raise ExperimentError("prompt/output-schema/validator schema file is missing")
    if health_checker is not None and not health_checker.is_file():
        raise ExperimentError(f"--health-checker file is missing: {health_checker}")
    if not args.dry_run and (kubeconfig is None or not kubeconfig.is_file() or not args.context):
        raise ExperimentError("live runs require an explicit readable --kubeconfig and --context")
    try:
        schema_value = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema_value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaError) as exc:
        raise ExperimentError(f"output schema is not a valid Draft 2020-12 schema: {exc}") from exc
    validator = Draft202012Validator(schema_value)
    try:
        output_schema_value = json.loads(output_schema_path.read_text(encoding="utf-8"))
        if not isinstance(output_schema_value, dict):
            raise ValueError("root is not an object")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ExperimentError(f"Codex output schema is not valid JSON: {exc}") from exc
    preflight: dict[str, Any] | None = None
    if not args.dry_run:
        assert kubeconfig is not None and args.context is not None
        preflight = _preflight_readonly_kubeconfig(
            kubectl_bin=args.kubectl_bin, kubeconfig=kubeconfig, context=args.context
        )
    kubernetes_api_host = preflight.pop("_api_host") if preflight is not None else None

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = (
        args.output.resolve()
        if args.output is not None
        else Path("/tmp") / f"codex-appservice-ab-{run_id}"
    )
    if output.is_relative_to(source):
        raise ExperimentError(
            "--output must be outside the appservice repository; experiment worktrees and "
            "private artifacts must not become repository inputs"
        )
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    private = output / "private"
    private.mkdir(mode=0o700)

    commit = _git(source, "rev-parse", "HEAD").decode().strip()
    status = _git(source, "status", "--porcelain=v1", "-z")
    dirty = bool(status)
    if dirty and not args.allow_dirty:
        raise ExperimentError(
            "appservice working tree is dirty; commit/stash it or rerun with --allow-dirty"
        )
    if args.include_untracked and not args.allow_dirty:
        raise ExperimentError("--include-untracked requires --allow-dirty")
    tracked_patch = _git(source, "diff", "--binary", "HEAD") if dirty else b""
    if dirty and tracked_patch and not args.allow_dirty:
        raise ExperimentError("tracked changes require --allow-dirty")

    worktrees_root = output / "worktrees"
    worktree_a = worktrees_root / "A"
    worktree_b = worktrees_root / "B"
    untracked_counts = {"A": 0, "B": 0}

    launcher = shlex.split(args.outctl_cmd)
    if not launcher:
        raise ExperimentError("--outctl-cmd resolved to an empty command")
    # The launcher supplies the explicit scoped kubeconfig directly.  Do not
    # invoke direnv inside the least-privilege Codex sandbox: it can touch
    # user-local state that is unrelated to this fixed corpus.
    router = Path(__file__).with_name("outctl_kubectl_router.py").resolve()
    router_exec, router_common = _router_prefixes(
        kubeconfig=kubeconfig, router=router, launcher=launcher
    )
    retrieval_prefix = f"{router_exec} tail {router_common}"
    wrapper = (
        f"{router_exec} run {router_common} "
        f"--policy-ref {shlex.quote(args.policy_ref)} "
        f"--policy-digest {shlex.quote(args.policy_digest)} "
        "--"
    )

    prompt_template = prompt_path.read_text(encoding="utf-8")
    placeholder = "{{CANONICAL_APPSERVICE}}"
    if prompt_template.count(placeholder) != 1:
        raise ExperimentError(f"prompt template must contain exactly one {placeholder} placeholder")
    prompt = prompt_template.replace(placeholder, str(canonical))
    auth_candidate = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "auth.json"
    auth_source = auth_candidate if auth_candidate.is_file() else None
    if not args.dry_run and auth_source is None and not os.environ.get("CODEX_API_KEY"):
        raise ExperimentError(f"no Codex auth found at {auth_candidate} and CODEX_API_KEY is unset")

    started_at = _utc_now()
    shared_checker: dict[str, Any] | None = None
    if health_checker is not None:
        if args.dry_run:
            shared_checker = {"planned": True, "path": str(health_checker)}
        else:
            assert kubeconfig is not None
            text, shared_checker = _run_shared_health_checker(
                launcher=launcher,
                checker=health_checker,
                cwd=canonical,
                kubeconfig=kubeconfig,
                spool_root=private / "shared-health-checker-spool",
                policy_ref=args.policy_ref,
                policy_digest=args.policy_digest,
            )
            prompt += "\n\nShared bounded appservice health-checker evidence:\n" + text
    pairs: list[dict[str, Any]] = []
    try:
        untracked_counts["A"] = _prepare_worktree(
            source,
            worktree_a,
            commit,
            tracked_patch=tracked_patch if args.allow_dirty else None,
            include_untracked=args.include_untracked,
        )
        untracked_counts["B"] = _prepare_worktree(
            source,
            worktree_b,
            commit,
            tracked_patch=tracked_patch if args.allow_dirty else None,
            include_untracked=args.include_untracked,
        )

        contamination = _find_outctl_guidance(worktree_b)
        if contamination and not args.allow_contaminated_baseline:
            raise ExperimentError(
                "arm B baseline already contains native outctl guidance: "
                + ", ".join(contamination)
                + "; remove it or use --allow-contaminated-baseline with an explicit caveat"
            )

        baseline_hooks_sha256 = _sha256_file(worktree_b / ".codex" / "hooks.json")
        _append_arm_a_guidance(worktree_a, wrapper, retrieval_prefix)
        _install_guard(worktree_a, arm="A", wrapper=wrapper)
        _install_guard(worktree_b, arm="B", wrapper=wrapper)
        baseline_overlay_contamination = _find_outctl_guidance(worktree_b)
        newly_introduced_contamination = sorted(
            set(baseline_overlay_contamination) - set(contamination)
        )
        if newly_introduced_contamination:
            raise ExperimentError(
                "experiment implementation contaminated arm B with outctl guidance: "
                + ", ".join(newly_introduced_contamination)
            )
        guidance_inventory: dict[str, Any] = {
            "A": _guidance_inventory(worktree_a),
            "B": _guidance_inventory(worktree_b),
        }
        guidance_inventory["delta_bytes_a_minus_b"] = int(guidance_inventory["A"]["bytes"]) - int(
            guidance_inventory["B"]["bytes"]
        )

        planned_commands: list[dict[str, Any]] = []
        for pair_index in range(1, args.pairs + 1):
            pair_dir = private / f"pair-{pair_index:03d}"
            home_a = pair_dir / "codex-home-A"
            home_b = pair_dir / "codex-home-B"
            arm_dir_a = pair_dir / "A"
            arm_dir_b = pair_dir / "B"
            spool_a = pair_dir / "outctl-spool-A"
            for path in (arm_dir_a, arm_dir_b, spool_a, spool_a / "uv-cache", spool_a / "tmp"):
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o700)
            _write_codex_home(
                home_a,
                worktree=worktree_a,
                canonical=canonical,
                outctl_project=Path(__file__).resolve().parents[2],
                write_roots=(spool_a, arm_dir_a),
                kubernetes_api_host=kubernetes_api_host,
                auth_source=auth_source,
                reasoning_effort=args.reasoning_effort,
            )
            _write_codex_home(
                home_b,
                worktree=worktree_b,
                canonical=canonical,
                outctl_project=Path(__file__).resolve().parents[2],
                write_roots=(arm_dir_b,),
                kubernetes_api_host=kubernetes_api_host,
                auth_source=auth_source,
                reasoning_effort=args.reasoning_effort,
            )
            _install_home_hook(home_a, worktree_a, arm="A")
            _install_home_hook(home_b, worktree_b, arm="B")
            command_a = _build_codex_command(
                codex_bin=args.codex_bin,
                model=args.model,
                worktree=worktree_a,
                schema=output_schema_path,
                final_path=arm_dir_a / "final.json",
                prompt=prompt,
                additional_write_dirs=(spool_a,),
            )
            command_b = _build_codex_command(
                codex_bin=args.codex_bin,
                model=args.model,
                worktree=worktree_b,
                schema=output_schema_path,
                final_path=arm_dir_b / "final.json",
                prompt=prompt,
            )
            planned_commands.append(
                {
                    "pair": pair_index,
                    "A": command_a[:-1] + ["<identical prompt>"],
                    "B": command_b[:-1] + ["<identical prompt>"],
                }
            )
            if args.dry_run:
                _remove_codex_home(home_a)
                _remove_codex_home(home_b)
                continue

            base_env = os.environ.copy()
            # Never allow either arm to inherit a workstation/admin kubeconfig.
            base_env.pop("KUBECONFIG", None)
            env_a = {
                **base_env,
                "CODEX_HOME": str(home_a),
                "CODEX_AB_ARM": "A",
                "CODEX_AB_EXPERIMENT_ID": run_id,
                "CODEX_AB_HOOK_LOG": str(arm_dir_a / "hook-events.jsonl"),
                "KUBECONFIG": str(kubeconfig),
                "OUTCTL_AB_SPOOL_ROOT": str(spool_a),
                "OUTCTL_ENABLED": "1",
                "OUTCTL_MODE": "enforce",
            }
            env_b = {
                **base_env,
                "CODEX_HOME": str(home_b),
                "CODEX_AB_ARM": "B",
                "CODEX_AB_EXPERIMENT_ID": run_id,
                "CODEX_AB_HOOK_LOG": str(arm_dir_b / "hook-events.jsonl"),
                "KUBECONFIG": str(kubeconfig),
            }

            barrier = threading.Barrier(3)
            process_results: dict[str, ProcessResult] = {}
            thread_errors: dict[str, Exception] = {}
            lock = threading.Lock()

            def worker(
                arm: str,
                command: list[str],
                env: Mapping[str, str],
                arm_dir: Path,
                *,
                barrier: threading.Barrier = barrier,
                lock: threading.Lock = lock,
                process_results: dict[str, ProcessResult] = process_results,
                thread_errors: dict[str, Exception] = thread_errors,
            ) -> None:
                try:
                    result = _run_arm(
                        arm=arm,
                        command=command,
                        env=env,
                        output_dir=arm_dir,
                        timeout_seconds=args.timeout_seconds,
                        barrier=barrier,
                    )
                    with lock:
                        process_results[arm] = result
                except Exception as worker_error:  # captured and re-raised in main thread
                    with lock:
                        thread_errors[arm] = worker_error

            threads = {
                "A": threading.Thread(
                    target=worker, args=("A", command_a, env_a, arm_dir_a), daemon=False
                ),
                "B": threading.Thread(
                    target=worker, args=("B", command_b, env_b, arm_dir_b), daemon=False
                ),
            }
            thread_start_order = ["A", "B"] if pair_index % 2 else ["B", "A"]
            for arm in thread_start_order:
                threads[arm].start()
            try:
                barrier.wait(timeout=START_BARRIER_TIMEOUT_SECONDS)
            except threading.BrokenBarrierError as exc:
                for thread in threads.values():
                    thread.join(timeout=START_BARRIER_TIMEOUT_SECONDS)
                raise ExperimentError(
                    "concurrent arm start barrier failed before both workers were ready"
                ) from exc
            for thread in threads.values():
                thread.join()
            _remove_codex_home(home_a)
            _remove_codex_home(home_b)

            if thread_errors:
                raise ExperimentError(
                    "arm execution failed: "
                    + "; ".join(f"{arm}: {exc}" for arm, exc in thread_errors.items())
                )
            if set(process_results) != {"A", "B"}:
                raise ExperimentError("did not receive process results for both arms")

            result_a = process_results["A"]
            result_b = process_results["B"]
            launch_skew_ms = (
                abs(result_a.launched_monotonic_ns - result_b.launched_monotonic_ns) / 1_000_000
            )
            arm_a, signature_a = _parse_arm(
                result_a,
                requested_model=args.model,
                validator=validator,
            )
            arm_b, signature_b = _parse_arm(
                result_b,
                requested_model=args.model,
                validator=validator,
            )
            comparison = _compare_pair(arm_a, arm_b, signature_a, signature_b, launch_skew_ms)
            pairs.append(
                {
                    "pair": pair_index,
                    "thread_start_order": thread_start_order,
                    "arms": {
                        "A": {"treatment": "guided_outctl", **arm_a},
                        "B": {"treatment": "unguided_native", **arm_b},
                    },
                    "comparison": comparison,
                }
            )
            if _commissioning_failed(arm_a):
                break

        _write_json_private(output / "planned-commands.json", planned_commands)
        if args.dry_run:
            report = {
                "experiment": {
                    "id": run_id,
                    "dry_run": True,
                    "created_at": _utc_now(),
                    "appservice_commit": commit,
                    "worktree_a": str(worktree_a),
                    "worktree_b": str(worktree_b),
                    "wrapper": wrapper,
                    "baseline_outctl_guidance": contamination,
                    "baseline_overlay_outctl_guidance": baseline_overlay_contamination,
                    "baseline_hooks_json_sha256": baseline_hooks_sha256,
                    "detached_worktree_hooks_mode": "experiment-only hooks.json in both arms",
                    "prompt_template_sha256": _sha256_file(prompt_path),
                    "rendered_prompt_sha256": _sha256_text(prompt),
                    "rendered_prompt_bytes": len(prompt.encode("utf-8")),
                    "model_guidance_inventory": guidance_inventory,
                    "shared_health_checker": shared_checker,
                }
            }
        else:
            report = {
                "experiment": {
                    "id": run_id,
                    "started_at": started_at,
                    "completed_at": _utc_now(),
                    "appservice_commit": commit,
                    "source_dirty": dirty,
                    "tracked_patch_sha256": _sha256_bytes(tracked_patch) if tracked_patch else None,
                    "included_untracked_files": untracked_counts,
                    "model_requested": args.model,
                    "codex_version": _codex_version(args.codex_bin),
                    "permissions": {
                        "profile": PERMISSION_PROFILE_NAME,
                        "approval_policy": "never",
                        "sandbox_override": None,
                        "additional_write_roots": {"A": ["outctl_spool"], "B": []},
                        "network": "one verified Kubernetes API host per run",
                    },
                    "preflight": preflight,
                    "reasoning_effort": args.reasoning_effort,
                    "pairs_requested": args.pairs,
                    "pairs_executed": len(pairs),
                    "aborted_after_commissioning_failure": (
                        len(pairs) < args.pairs and _commissioning_failed(arm_a)
                    ),
                    "prompt_template_sha256": _sha256_file(prompt_path),
                    "rendered_prompt_sha256": _sha256_text(prompt),
                    "rendered_prompt_bytes": len(prompt.encode("utf-8")),
                    "output_schema_sha256": _sha256_file(schema_path),
                    "codex_output_schema_sha256": _sha256_file(output_schema_path),
                    "policy_ref": args.policy_ref,
                    "policy_digest": args.policy_digest,
                    "shared_health_checker": shared_checker,
                    "baseline_native_outctl_guidance": contamination,
                    "baseline_hooks_json_sha256": baseline_hooks_sha256,
                    "model_guidance_inventory": guidance_inventory,
                    "detached_worktree_hooks_mode": (
                        "experiment-only hooks.json in both arms; any baseline hook file is "
                        "recorded by digest and not activated"
                    ),
                    "rate_date": RATE_DATE,
                    "rate_card": {
                        "codex_credits_per_million": TERRA_CODEX_CREDITS_PER_M,
                        "api_usd_per_million": TERRA_API_USD_PER_M,
                        "api_long_context_threshold_input_tokens": LONG_CONTEXT_THRESHOLD,
                        "codex_credit_scope": (
                            "current token-based Codex rate card; a small legacy Enterprise subset "
                            "may use different accounting"
                        ),
                        "api_equivalent_scope": (
                            "comparison value only when signed in with ChatGPT; not an "
                            "asserted bill"
                        ),
                    },
                    "hook_trust": (
                        "--dangerously-bypass-hook-trust is used only for generated, hashed, "
                        "experiment-local hook sources; baseline project hooks are not loaded"
                    ),
                    "telemetry_contract": (
                        "final turn.completed usage; command_execution aggregated_output bytes; "
                        "PreToolUse model/compliance telemetry; raw-free outctl manifest "
                        "byte totals"
                    ),
                    "memory_proxy_note": (
                        "Codex exposes token processing and cache categories, not literal resident "
                        "session-memory bytes. Total input, uncached input, cache hit ratio, and "
                        "model-visible command-output bytes are the experiment proxies."
                    ),
                    "cache_interpretation_note": (
                        "Absolute cached tokens are not a lower-is-better metric. Prefer total "
                        "input, uncached read input, weighted credits/cost, and cache-hit ratio. "
                        "Concurrent "
                        "arms may share backend cache for common prefixes."
                    ),
                },
                "pairs": pairs,
                "aggregate": _aggregate_pairs(pairs),
            }
        _write_json_private(output / "report.json", report)
        print(str(output / "report.json"))
        if not args.dry_run and not bool(report["aggregate"]["all_pairs_valid"]):
            return 1
        return 0
    finally:
        # Remove any credential-bearing homes even after a failure.
        for home in private.glob("pair-*/codex-home-*"):
            _remove_codex_home(home)
        if not args.keep_worktrees:
            for worktree in (worktree_a, worktree_b):
                if worktree.exists():
                    _run(
                        ["git", "-C", str(source), "worktree", "remove", "--force", str(worktree)],
                        check=False,
                    )
            _run(["git", "-C", str(source), "worktree", "prune"], check=False)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ExperimentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
