#!/usr/bin/env python3
"""Expose only bounded outctl projection text to a Codex A/B treatment arm.

The router never reads capture files.  It invokes the existing outctl CLI,
parses its bounded JSON envelope, and writes a deliberately small response for
the model: a capture identifier, command status, and safe inline projection.
Raw capture bytes remain in the outctl spool.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Any

from semantic_pods import (
    SemanticPodError,
    is_exact_unfiltered_inventory,
    project_pod_inventory,
)


def _outctl_command(value: str) -> list[str]:
    parsed = json.loads(value)
    if (
        not isinstance(parsed, list)
        or not parsed
        or not all(isinstance(item, str) for item in parsed)
    ):
        raise ValueError("--outctl-command-json must be a non-empty JSON argv array")
    return parsed


def _safe_envelope(stdout: bytes) -> tuple[str, int | None, str]:
    value: Any = json.loads(stdout.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("outctl response must be an object")
    receipt = value.get("receipt")
    envelope = value.get("envelope")
    capture_id = receipt.get("capture_id") if isinstance(receipt, dict) else value.get("capture_id")
    command = value.get("command")
    exit_code = command.get("exit_code") if isinstance(command, dict) else None
    projection = (
        envelope.get("projection") if isinstance(envelope, dict) else value.get("projection")
    )
    text = (
        projection.get("inline_text", projection.get("text"))
        if isinstance(projection, dict)
        else None
    )
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError("outctl response lacks a capture identifier")
    if exit_code is not None and not isinstance(exit_code, int):
        raise ValueError("outctl response has an invalid command exit status")
    if not isinstance(text, str):
        raise ValueError("outctl response lacks a safe projection")
    return capture_id, exit_code, text


def _emit(capture_id: str, exit_code: int | None, text: str) -> None:
    print(f"capture_id: {capture_id}")
    print(f"command_exit_code: {exit_code if exit_code is not None else 'signal'}")
    print("bounded_projection:")
    sys.stdout.write(text)
    if not text.endswith("\n"):
        print()


def _record_router_event(
    spool_root: str,
    *,
    action: str,
    capture_id: str,
    exit_code: int | None,
    text: str,
    projection_profile: str,
    semantic_applied: bool = False,
) -> None:
    """Persist structured provenance beside the private spool.

    This sidecar is harness metadata, not model-visible command output.  It
    lets the report bind a final ``evidence_ref`` to the capture and operation
    that actually produced it, including exact/native-like pass-through.
    """

    root = Path(spool_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / "router-events.jsonl"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        value = {
            "action": action,
            "capture_id": capture_id,
            "operation": "projection" if action == "run" else action,
            "stream": "stdout" if action in {"tail", "search", "search-many"} else None,
            "start": None,
            "end": None,
            "exit_code": exit_code,
            "projection_profile": projection_profile,
            "semantic_applied": semantic_applied,
            "projection_sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
        os.write(descriptor, (json.dumps(value, sort_keys=True) + "\n").encode())
    finally:
        os.close(descriptor)


def _search_redactions() -> tuple[str, ...]:
    """Load exact redactions supplied only by the trusted harness boundary."""
    raw = os.environ.get("OUTCTL_ROUTER_REDACT_EXACT_JSON")
    if raw is None:
        return ()
    value = json.loads(raw)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError("OUTCTL_ROUTER_REDACT_EXACT_JSON must be a JSON string array")
    return tuple(value)


def _safe_search(stdout: bytes, *, exact_redactions: Sequence[str] = ()) -> tuple[str, str]:
    """Validate and bound projected ``outctl search`` windows."""
    value: Any = json.loads(stdout.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("outctl search response must be an object")
    capture_id = value.get("capture_id")
    matches = value.get("matches")
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError("outctl search response lacks a capture identifier")
    if not isinstance(matches, list):
        raise ValueError("outctl search response lacks matches")
    lines: list[str] = []
    budget = 2_048
    for index, match in enumerate(matches[:3], start=1):
        if not isinstance(match, dict):
            raise ValueError("outctl search response has an invalid match")
        projection = match.get("projection")
        text = projection.get("text") if isinstance(projection, dict) else None
        if not isinstance(text, str):
            raise ValueError("outctl search response lacks a safe projection")
        for value in exact_redactions:
            text = text.replace(value, "[REDACTED]")
        text = f"match {index}:\n{text}"
        encoded = text.encode("utf-8")
        if len(encoded) > budget:
            text = encoded[:budget].decode("utf-8", errors="ignore")
            lines.append(text + "\n[... search output omitted ...]")
            break
        lines.append(text)
        budget -= len(encoded)
        if budget <= 0:
            break
    return capture_id, "\n".join(lines) if lines else "no bounded matches"


def _emit_search(capture_id: str, text: str) -> None:
    print(f"capture_id: {capture_id}")
    print("bounded_search:")
    sys.stdout.write(text)
    if not text.endswith("\n"):
        print()


def _safe_search_many(
    stdout: bytes, *, exact_redactions: Sequence[str] = ()
) -> tuple[str, str]:
    value: Any = json.loads(stdout.decode("utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("queries"), list):
        raise ValueError("outctl search-many response lacks queries")
    capture_id = value.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError("outctl search-many response lacks a capture identifier")
    sections: list[str] = []
    budget = 4_096
    for query in value["queries"]:
        if not isinstance(query, dict) or not isinstance(query.get("pattern"), str):
            raise ValueError("outctl search-many response has an invalid query")
        nested = {"capture_id": capture_id, "matches": query.get("matches")}
        _, projected = _safe_search(
            json.dumps(nested).encode(), exact_redactions=exact_redactions
        )
        section = f"literal {query['pattern']!r}:\n{projected}"
        encoded = section.encode("utf-8")
        if len(encoded) > budget:
            sections.append(encoded[:budget].decode("utf-8", errors="ignore"))
            break
        sections.append(section)
        budget -= len(encoded)
    return capture_id, "\n".join(sections)


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes] | int:
    return subprocess.run(
        list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
    )


def _acquire_spool_lock(spool_root: str) -> IO[bytes]:
    """Serialize one arm's commands while leaving the two A/B arms concurrent."""
    root = Path(spool_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = root / ".router.lock"
    handle = lock_path.open("a+b")
    os.chmod(lock_path, 0o600)
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    if not values or values[0] not in {"run", "tail", "search", "search-many"}:
        parser.error("first argument must be run, tail, search, or search-many")
    action = values.pop(0)
    parser.add_argument("--outctl-command-json", required=True)
    parser.add_argument("--kubectl-command-json")
    parser.add_argument("--spool-root", required=True)
    parser.add_argument("--policy-ref")
    parser.add_argument("--policy-digest")
    parser.add_argument(
        "--projection-profile",
        choices=("generic", "exact", "semantic-pods"),
        default="generic",
        help="bounded backend presentation profile; semantic-pods is exact-shape only",
    )
    parser.add_argument("capture_id", nargs="?")
    parser.add_argument("--lines", type=int, default=80)
    parser.add_argument("--max-matches", type=int, default=3)
    parser.add_argument("pattern", nargs="?")
    parser.add_argument("--literal", action="append", dest="literals")
    command: list[str] = []
    if action == "run":
        if "--" not in values:
            parser.error("run requires direct argv after --")
        separator = values.index("--")
        command = values[separator + 1 :]
        values = values[:separator]
    args = parser.parse_args(values)
    args.action = action
    try:
        outctl = _outctl_command(args.outctl_command_json)
        kubectl_prefix = (
            _outctl_command(args.kubectl_command_json)
            if args.kubectl_command_json is not None
            else None
        )
    except (ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.action == "run":
        if not command:
            parser.error("run requires direct argv after --")
        if not args.policy_ref or not args.policy_digest:
            parser.error("run requires --policy-ref and --policy-digest")
        if command[0] == "kubectl" and kubectl_prefix is not None:
            command = [*kubectl_prefix, *command[1:]]
        command = [
            *outctl,
            "run",
            "--mode",
            "enforce",
            "--spool-root",
            args.spool_root,
            "--policy-ref",
            args.policy_ref,
            "--policy-digest",
            args.policy_digest,
            "--max-projection-bytes",
            "1048576" if args.projection_profile in {"exact", "semantic-pods"} else "4096",
            "--max-projection-lines",
            "100000" if args.projection_profile in {"exact", "semantic-pods"} else "120",
            "--max-projection-tokens",
            "262144" if args.projection_profile in {"exact", "semantic-pods"} else "1024",
            "--",
            *command,
        ]
    elif args.action == "tail":
        if not args.capture_id:
            parser.error("tail requires a capture identifier")
        command = [
            *outctl,
            "tail",
            "--spool-root",
            args.spool_root,
            args.capture_id,
            "stdout",
            "--lines",
            str(args.lines),
            "--max-bytes",
            "2048",
        ]
    elif args.action == "search":
        if not args.capture_id or not args.pattern:
            parser.error("search requires a capture identifier and literal pattern")
        if not 1 <= args.max_matches <= 3:
            parser.error("--max-matches must be between 1 and 3")
        command = [
            *outctl,
            "search",
            "--spool-root",
            args.spool_root,
            args.capture_id,
            "stdout",
            args.pattern,
            "--context-bytes",
            "160",
            "--max-matches",
            str(args.max_matches),
        ]
    else:
        if not args.capture_id or not args.literals:
            parser.error("search-many requires a capture identifier and --literal values")
        command = [
            *outctl,
            "search-many",
            "--spool-root",
            args.spool_root,
            args.capture_id,
            "stdout",
            *args.literals,
            "--context-bytes",
            "160",
            "--max-matches-per-pattern",
            str(args.max_matches),
        ]
    spool_lock = _acquire_spool_lock(args.spool_root)
    try:
        if args.action in {"search", "search-many"}:
            completed = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
            )
            try:
                parser_fn = _safe_search if args.action == "search" else _safe_search_many
                capture_id, text = parser_fn(
                    completed.stdout, exact_redactions=_search_redactions()
                )
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                print(
                    "outctl router could not read a bounded search response: "
                    f"{exc}; outctl_exit={completed.returncode}; "
                    f"stdout_bytes={len(completed.stdout)}",
                    file=sys.stderr,
                )
                return 1
            _emit_search(capture_id, text)
            _record_router_event(
                args.spool_root,
                action=args.action,
                capture_id=capture_id,
                exit_code=completed.returncode,
                text=text,
                projection_profile=args.projection_profile,
            )
            return completed.returncode

        completed = _run(command)
        # Keep the command-construction seam easy to unit-test without
        # fabricating a model-facing envelope.
        if isinstance(completed, int):
            return completed
        try:
            capture_id, exit_code, text = _safe_envelope(completed.stdout)
            semantic_applied = False
            if args.projection_profile == "semantic-pods" and "--" in command:
                logical_argv = command[command.index("--") + 1 :]
                if is_exact_unfiltered_inventory(logical_argv):
                    semantic_applied = True
            if semantic_applied:
                try:
                    text = project_pod_inventory(logical_argv, text)
                except (SemanticPodError, ValueError, json.JSONDecodeError) as exc:
                    print(f"semantic pod projection rejected: {exc}", file=sys.stderr)
                    return 2
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            print(
                "outctl router could not read a bounded envelope: "
                f"{exc}; outctl_exit={completed.returncode}; "
                f"stdout_bytes={len(completed.stdout)}",
                file=sys.stderr,
            )
            return 1
        _emit(capture_id, exit_code, text)
        _record_router_event(
            args.spool_root,
            action="run",
            capture_id=capture_id,
            exit_code=exit_code,
            text=text,
            projection_profile=args.projection_profile,
            semantic_applied=semantic_applied,
        )
        return completed.returncode
    finally:
        spool_lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
