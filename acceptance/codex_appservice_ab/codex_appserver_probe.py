#!/usr/bin/env python3
"""Capture a minimal Codex app-server run with raw Responses items enabled.

Unlike ``codex exec --json``, the app-server has an internal raw-event opt-in
(``experimentalRawEvents``).  The probe preserves every app-server JSON-RPC
line, then runs the structural trace handler over that private stream.  It is
read-only, ephemeral, bounded by a turn timeout, and intended only for
commissioning the observer—not for decision-bearing A/B evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import select
import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from trace_handler import TraceCaptureError, capture_runtime_trace

DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_EFFORT = "low"
DEFAULT_TIMEOUT_SECONDS = 180
PROBE_SCHEMA_VERSION = "vuoro.outctl.codex-appserver-probe/v1"


class ProbeError(RuntimeError):
    """Raised when the app-server probe cannot complete safely."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def _send(process: subprocess.Popen[bytes], request: Mapping[str, Any]) -> None:
    payload = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert process.stdin is not None
    process.stdin.write(payload + b"\n")
    process.stdin.flush()


def _read_line(
    process: subprocess.Popen[bytes], events: Any, deadline: float
) -> Mapping[str, Any]:
    assert process.stdout is not None
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [process.stdout], [], [], max(0.0, deadline - time.monotonic())
        )
        if not ready:
            raise ProbeError("app-server probe timed out")
        raw_line = process.stdout.readline()
        if not raw_line:
            raise ProbeError("app-server closed stdout before the probe completed")
        events.write(raw_line)
        try:
            value = json.loads(raw_line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ProbeError(f"app-server emitted invalid JSON: {exc}") from exc
        if isinstance(value, Mapping):
            return value
        raise ProbeError("app-server emitted a non-object JSON value")
    raise ProbeError("app-server probe timed out")


def _read_until(
    process: subprocess.Popen[bytes], events: Any, request_id: int, deadline: float
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]]:
    notifications: list[Mapping[str, Any]] = []
    while True:
        value = _read_line(process, events, deadline)
        if value.get("id") == request_id:
            if "error" in value:
                raise ProbeError(f"app-server request {request_id} failed: {value['error']}")
            result = value.get("result")
            if not isinstance(result, Mapping):
                raise ProbeError(f"app-server request {request_id} returned no result")
            return result, notifications
        notifications.append(value)


def _method(value: Mapping[str, Any]) -> str | None:
    method = value.get("method")
    return method if isinstance(method, str) else None


def _thread_id(result: Mapping[str, Any]) -> str:
    thread = result.get("thread")
    if not isinstance(thread, Mapping) or not isinstance(thread.get("id"), str):
        raise ProbeError("thread/start did not return a thread id")
    return str(thread["id"])


def _turn_id(result: Mapping[str, Any]) -> str:
    turn = result.get("turn")
    if not isinstance(turn, Mapping) or not isinstance(turn.get("id"), str):
        raise ProbeError("turn/start did not return a turn id")
    return str(turn["id"])


def _is_turn_completed(value: Mapping[str, Any], thread_id: str, turn_id: str) -> bool:
    params = value.get("params")
    if not isinstance(params, Mapping) or params.get("threadId") != thread_id:
        return False
    method = _method(value)
    if method == "turn/completed":
        return params.get("turnId") == turn_id
    # The app-server currently settles a turn by changing the thread status
    # to idle; the CLI JSONL surface instead emits turn.completed.
    status = params.get("status")
    return method == "thread/status/changed" and isinstance(status, Mapping) and status.get(
        "type"
    ) == "idle"


def _safe_event_metrics(events_path: Path) -> dict[str, Any]:
    event_types: Counter[str] = Counter()
    item_types: Counter[str] = Counter()
    raw_response_items: Counter[str] = Counter()
    raw_response_count = 0
    latest_usage: dict[str, int] = {}
    line_count = 0
    invalid_lines = 0
    with events_path.open("rb") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            line_count += 1
            try:
                value = json.loads(raw_line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(value, Mapping):
                invalid_lines += 1
                continue
            method = value.get("method")
            if isinstance(method, str):
                event_types[method] += 1
                if method == "rawResponse/completed":
                    raw_response_count += 1
            params = value.get("params")
            if isinstance(params, Mapping):
                usage = params.get("usage")
                if method == "rawResponse/completed" and isinstance(usage, Mapping):
                    latest_usage = {
                        str(key): item
                        for key, item in usage.items()
                        if (
                            isinstance(key, str)
                            and isinstance(item, int)
                            and not isinstance(item, bool)
                        )
                    }
                item = params.get("item")
                if isinstance(item, Mapping) and isinstance(item.get("type"), str):
                    item_type = str(item["type"])
                    item_types[item_type] += 1
                    if isinstance(method, str) and "raw" in method.casefold():
                        raw_response_items[item_type] += 1
    return {
        "jsonl_lines": line_count,
        "invalid_jsonl_lines": invalid_lines,
        "event_methods": dict(sorted(event_types.items())),
        "param_item_types": dict(sorted(item_types.items())),
        "raw_response_item_types": dict(sorted(raw_response_items.items())),
        "raw_response_count": raw_response_count,
        "latest_cumulative_usage": latest_usage,
    }


def run_probe(
    *,
    output_root: Path,
    cwd: Path,
    model: str = DEFAULT_MODEL,
    effort: str = DEFAULT_EFFORT,
    prompt: str,
    codex_bin: str = "codex",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if timeout_seconds < 1:
        raise ProbeError("timeout_seconds must be positive")
    output_root.mkdir(parents=True, exist_ok=True)
    events_path = output_root / "app-server-events.jsonl"
    stderr_path = output_root / "app-server-stderr.log"
    trace_path = output_root / "runtime-trace.jsonl"
    trace_summary_path = output_root / "runtime-trace-summary.json"
    metrics_path = output_root / "metrics.json"

    command = [codex_bin, "app-server", "--stdio"]
    started_at = _utc_now()
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr_path.open("wb"),
    )
    deadline = started + timeout_seconds
    request_counter = 0
    notifications: list[Mapping[str, Any]] = []
    thread_id: str | None = None
    turn_id: str | None = None
    completed = False
    try:
        with events_path.open("wb") as events:
            events_path.chmod(0o600)
            request_counter += 1
            _send(
                process,
                {
                    "id": request_counter,
                    "method": "initialize",
                    "params": {
                        "clientInfo": {
                            "name": "outctl-codex-appserver-probe",
                            "version": "1.0.0",
                        },
                        "capabilities": {"experimentalApi": True},
                    },
                },
            )
            _, received = _read_until(process, events, request_counter, deadline)
            notifications.extend(received)

            request_counter += 1
            _send(
                process,
                {
                    "id": request_counter,
                    "method": "thread/start",
                    "params": {
                        "model": model,
                        "cwd": str(cwd),
                        "ephemeral": True,
                        "experimentalRawEvents": True,
                        "approvalPolicy": "never",
                        "sandbox": "read-only",
                        "serviceTier": "fast",
                        "personality": "pragmatic",
                    },
                },
            )
            result, received = _read_until(process, events, request_counter, deadline)
            notifications.extend(received)
            thread_id = _thread_id(result)

            request_counter += 1
            _send(
                process,
                {
                    "id": request_counter,
                    "method": "turn/start",
                    "params": {
                        "threadId": thread_id,
                        "input": [{"type": "text", "text": prompt, "text_elements": []}],
                        "model": model,
                        "effort": effort,
                        "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                    },
                },
            )
            result, received = _read_until(process, events, request_counter, deadline)
            notifications.extend(received)
            turn_id = _turn_id(result)

            while time.monotonic() < deadline:
                value = _read_line(process, events, deadline)
                notifications.append(value)
                if _is_turn_completed(value, thread_id, turn_id):
                    completed = True
                    break
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        stderr_path.chmod(0o600)

    if not completed:
        raise ProbeError("app-server turn did not complete")
    try:
        trace_summary = capture_runtime_trace(events_path, trace_path, trace_summary_path)
    except TraceCaptureError as exc:
        raise ProbeError(f"required trace handler failed: {exc}") from exc
    metrics = {
        "schema_version": PROBE_SCHEMA_VERSION,
        "status": "complete",
        "model": model,
        "effort": effort,
        "started_at": started_at,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "thread_id": thread_id,
        "turn_id": turn_id,
        "request": {
            "experimental_raw_events": True,
            "approval_policy": "never",
            "sandbox": "read-only",
            "ephemeral": True,
        },
        "transport": _safe_event_metrics(events_path),
        "trace": {
            "schema_version": trace_summary["schema_version"],
            "marker_presence": trace_summary["marker_presence"],
            "marker_counts": trace_summary["marker_counts"],
            "evidence_domains": trace_summary["evidence_domains"],
            "ptc_caller_graph": trace_summary["ptc_caller_graph"],
            "source": trace_summary["source"],
            "normalized_trace": trace_summary["normalized_trace"],
        },
        "private_artifacts": {
            "events": events_path.name,
            "stderr": stderr_path.name,
            "runtime_trace": trace_path.name,
            "runtime_trace_summary": trace_summary_path.name,
        },
    }
    _write_json(metrics_path, metrics)
    return metrics


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--effort", default=DEFAULT_EFFORT)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("prompt")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        metrics = run_probe(
            output_root=args.output,
            cwd=args.cwd,
            model=args.model,
            effort=args.effort,
            prompt=args.prompt,
            codex_bin=args.codex_bin,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, ProbeError) as exc:
        print(f"probe failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
