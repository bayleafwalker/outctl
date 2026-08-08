#!/usr/bin/env python3
"""Summarize cumulative Codex JSONL token usage and Terra cost accounting."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

import run as harness


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="codex exec --json event stream")
    parser.add_argument("--model", default="gpt-5.6-terra")
    parser.add_argument("--compact", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    events, warnings = harness._read_jsonl(args.events)
    try:
        usage, usage_warnings = harness._extract_usage(events)
    except harness.ExperimentError as exc:
        usage = None
        usage_warnings = [str(exc)]
    warnings.extend(usage_warnings)
    if usage is None:
        print(
            json.dumps(
                {
                    "status": "error",
                    "events": str(args.events),
                    "events_sha256": harness._sha256_file(args.events),
                    "warnings": warnings,
                },
                indent=None if args.compact else 2,
                sort_keys=True,
            )
        )
        return 2

    value = {
        "status": "ok",
        "events": str(args.events),
        "events_sha256": harness._sha256_file(args.events),
        "event_count": len(events),
        "usage": harness._usage_public(usage),
        "pricing": harness._cost_ranges(usage, model=args.model),
        "warnings": warnings,
    }
    print(
        json.dumps(
            value,
            indent=None if args.compact else 2,
            sort_keys=True,
            separators=(",", ":") if args.compact else None,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
