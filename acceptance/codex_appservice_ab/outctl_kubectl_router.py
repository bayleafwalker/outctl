#!/usr/bin/env python3
"""Expose only bounded outctl projection text to a Codex A/B treatment arm.

The router never reads capture files.  It invokes the existing outctl CLI,
parses its bounded JSON envelope, and writes a deliberately small response for
the model: a capture identifier, command status, and safe inline projection.
Raw capture bytes remain in the outctl spool.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from typing import Any


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
    capture_id = (
        receipt.get("capture_id")
        if isinstance(receipt, dict)
        else value.get("capture_id")
    )
    command = value.get("command")
    exit_code = command.get("exit_code") if isinstance(command, dict) else None
    projection = (
        envelope.get("projection")
        if isinstance(envelope, dict)
        else value.get("projection")
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


def _run(argv: Sequence[str]) -> int:
    completed = subprocess.run(
        list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
    )
    try:
        capture_id, exit_code, text = _safe_envelope(completed.stdout)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        # Do not expose child stderr: it may contain command output or secrets.
        # These bounded, raw-free facts are enough to distinguish an outctl
        # bootstrap failure from a malformed safe envelope during commissioning.
        print(
            "outctl router could not read a bounded envelope: "
            f"{exc}; outctl_exit={completed.returncode}; "
            f"stdout_bytes={len(completed.stdout)}",
            file=sys.stderr,
        )
        return 1
    _emit(capture_id, exit_code, text)
    return completed.returncode


def main(argv: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    if not values or values[0] not in {"run", "tail"}:
        parser.error("first argument must be run or tail")
    action = values.pop(0)
    parser.add_argument("--outctl-command-json", required=True)
    parser.add_argument("--spool-root", required=True)
    parser.add_argument("--policy-ref")
    parser.add_argument("--policy-digest")
    parser.add_argument("capture_id", nargs="?")
    parser.add_argument("--lines", type=int, default=80)
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
    except (ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if args.action == "run":
        if not command:
            parser.error("run requires direct argv after --")
        if not args.policy_ref or not args.policy_digest:
            parser.error("run requires --policy-ref and --policy-digest")
        command = [*outctl, "run", "--mode", "enforce", "--spool-root", args.spool_root,
                   "--policy-ref", args.policy_ref, "--policy-digest", args.policy_digest,
                   "--max-projection-bytes", "4096", "--max-projection-lines", "120",
                   "--max-projection-tokens", "1024", "--", *command]
    else:
        if not args.capture_id:
            parser.error("tail requires a capture identifier")
        command = [*outctl, "tail", "--spool-root", args.spool_root, args.capture_id,
                   "stdout", "--lines", str(args.lines), "--max-bytes", "2048"]
    return _run(command)


if __name__ == "__main__":
    raise SystemExit(main())
