#!/usr/bin/env python3
"""Offline, fail-closed kubectl replay for digest-bound controlled studies."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class ReplayError(RuntimeError):
    pass


def _load(path: Path, expected_digest: str) -> dict[str, Any]:
    body = path.read_bytes()
    observed = "sha256:" + hashlib.sha256(body).hexdigest()
    if observed != expected_digest:
        raise ReplayError("fixture digest mismatch")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ReplayError("fixture root must be an object")
    return value


def replay(fixture: dict[str, Any], argv: list[str]) -> dict[str, Any]:
    commands: dict[tuple[str, ...], Any] = {
        ("version", "-o", "json"): {
            "clientVersion": {"gitVersion": "v1.34.0-replay"},
            "serverVersion": {"gitVersion": "v1.34.0-replay"},
            "api": fixture.get("api"),
        },
        ("get", "nodes", "-o", "json"): {"items": fixture.get("nodes", [])},
        ("get", "pods", "-A", "-o", "json"): {"items": fixture.get("pods", [])},
        ("-n", "flux-system", "get", "pods", "-o", "json"): {
            "items": [fixture.get("gitops", {})]
        },
        (
            "-n", "gatus", "get", "deployments,persistentvolumeclaims", "-o", "json",
        ): {
            "deployments": [{"name": "gatus", "ready": True}],
            "persistentvolumeclaims": [fixture.get("storage", {})],
        },
        (
            "-n", "gatus", "get", "events", "--field-selector", "type=Warning",
            "--sort-by=.metadata.creationTimestamp", "-o", "json",
        ): {"items": fixture.get("events", [])},
    }
    key = tuple(argv)
    if key not in commands:
        raise ReplayError("command is outside the frozen replay corpus")
    return commands[key]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-sha256", required=True)
    known, command = parser.parse_known_args(argv)
    try:
        fixture = _load(known.fixture, known.fixture_sha256)
        result = replay(fixture, command)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReplayError) as exc:
        print(f"kubectl replay rejected: {exc}", file=sys.stderr)
        return 64
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
