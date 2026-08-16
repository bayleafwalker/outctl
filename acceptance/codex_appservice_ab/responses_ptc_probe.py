#!/usr/bin/env python3
"""Minimal Responses API PTC commissioning probe.

This is intentionally separate from the Codex CLI A/B runner.  It exercises
the Responses API contract that exposes ``program``/``function_call``/
``program_output`` items and records enough private raw material to validate
the caller graph, latency, response/continuation counts, tool calls, and
usage.  Normalized traces are metadata-only through ``trace_handler.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from trace_handler import TraceCaptureError, capture_runtime_trace

DEFAULT_MODEL = "gpt-5.6-terra"
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MAX_RESPONSES = 8
DEFAULT_TIMEOUT_SECONDS = 180
PROBE_SCHEMA_VERSION = "vuoro.outctl.responses-ptc-probe/v1"


class ProbeError(RuntimeError):
    """Raised when the PTC probe cannot complete a bounded run."""


class ResponseTransport(Protocol):
    def create(self, payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], bytes, float]:
        """Return parsed response JSON, exact response bytes, and latency."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def _append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as handle:
        handle.write(_canonical_json(value) + b"\n")
    path.chmod(0o600)


def _safe_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _usage_metrics(usage: Any) -> dict[str, int]:
    if not isinstance(usage, Mapping):
        return {}
    result: dict[str, int] = {}
    for key in (
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cached_tokens",
        "cache_read_input_tokens",
        "cache_write_input_tokens",
        "reasoning_tokens",
    ):
        number = _safe_int(usage.get(key))
        if number is not None:
            result[key] = number
    input_details = usage.get("input_tokens_details")
    if isinstance(input_details, Mapping):
        cached = _safe_int(input_details.get("cached_tokens"))
        if cached is not None:
            result.setdefault("cached_tokens", cached)
    output_details = usage.get("output_tokens_details")
    if isinstance(output_details, Mapping):
        reasoning = _safe_int(output_details.get("reasoning_tokens"))
        if reasoning is not None:
            result.setdefault("reasoning_tokens", reasoning)
    return result


def _add_usage(total: dict[str, int], current: Mapping[str, int]) -> None:
    for key, value in current.items():
        total[key] = total.get(key, 0) + value


def _tool_definition(
    name: str,
    description: str,
    properties: Mapping[str, Any],
    output: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": dict(properties),
            "required": ["sku"],
            "additionalProperties": False,
        },
        "output_schema": output,
        "allowed_callers": ["programmatic"],
        "strict": True,
    }


def default_tools() -> list[dict[str, Any]]:
    """Return two deterministic, read-only tools that make PTC observable."""
    return [
        _tool_definition(
            "get_inventory",
            "Return sku and available_units for a read-only inventory lookup.",
            {"sku": {"type": "string"}},
            {
                "type": "object",
                "properties": {"sku": {"type": "string"}, "available_units": {"type": "number"}},
                "required": ["sku", "available_units"],
                "additionalProperties": False,
            },
        ),
        _tool_definition(
            "get_demand",
            "Return sku and requested_units for a read-only demand lookup.",
            {"sku": {"type": "string"}},
            {
                "type": "object",
                "properties": {"sku": {"type": "string"}, "requested_units": {"type": "number"}},
                "required": ["sku", "requested_units"],
                "additionalProperties": False,
            },
        ),
        {"type": "programmatic_tool_calling"},
    ]


def default_implementations() -> dict[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]]:
    return {
        "get_inventory": lambda args: {"sku": str(args["sku"]), "available_units": 42},
        "get_demand": lambda args: {"sku": str(args["sku"]), "requested_units": 31},
    }


class UrllibResponseTransport:
    """Small stdlib-only Responses API transport for the live probe."""

    def __init__(self, api_key: str, base_url: str, timeout_seconds: int) -> None:
        self._api_key = api_key
        self._url = base_url.rstrip("/") + "/responses"
        self._timeout_seconds = timeout_seconds

    def create(self, payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], bytes, float]:
        body = _canonical_json(payload)
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                response_body = response.read()
        except urllib.error.HTTPError as exc:
            raise ProbeError(f"Responses API returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ProbeError(f"Responses API request failed: {exc.reason}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000
        try:
            parsed = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProbeError("Responses API returned invalid JSON") from exc
        if not isinstance(parsed, Mapping):
            raise ProbeError("Responses API returned a non-object JSON value")
        return parsed, response_body, elapsed_ms


@dataclass
class _ProbeAccumulator:
    response_count: int = 0
    continuation_count: int = 0
    tool_call_count: int = 0
    function_call_output_count: int = 0
    item_counts: Counter[str] = field(default_factory=Counter)
    statuses: Counter[str] = field(default_factory=Counter)
    response_latencies_ms: list[float] = field(default_factory=list)
    usage_total: dict[str, int] = field(default_factory=dict)
    response_usage: list[dict[str, Any]] = field(default_factory=list)
    final_message_count: int = 0
    final_output_text_bytes: int = 0
    final_output_text_sha256: str | None = None

    def record(self, response: Mapping[str, Any], latency_ms: float) -> list[Mapping[str, Any]]:
        self.response_count += 1
        if self.response_count > 1:
            self.continuation_count += 1
        self.response_latencies_ms.append(round(latency_ms, 3))
        status = response.get("status")
        if isinstance(status, str):
            self.statuses[status] += 1
        usage = _usage_metrics(response.get("usage"))
        _add_usage(self.usage_total, usage)
        self.response_usage.append(usage)
        output = response.get("output")
        if not isinstance(output, Sequence) or isinstance(output, (str, bytes, bytearray)):
            return []
        calls: list[Mapping[str, Any]] = []
        for item in output:
            if not isinstance(item, Mapping):
                continue
            item_type = item.get("type")
            if isinstance(item_type, str):
                self.item_counts[item_type] += 1
                if item_type == "function_call":
                    self.tool_call_count += 1
                    calls.append(item)
                elif item_type == "function_call_output":
                    self.function_call_output_count += 1
                elif item_type == "message":
                    self.final_message_count += 1
        output_text = response.get("output_text")
        if isinstance(output_text, str):
            encoded = output_text.encode("utf-8")
            self.final_output_text_bytes = len(encoded)
            self.final_output_text_sha256 = _sha256_bytes(encoded)
        return calls

    def public(self, *, model: str, started_at: str, finished_at: str) -> dict[str, Any]:
        return {
            "schema_version": PROBE_SCHEMA_VERSION,
            "probe": "responses_ptc_probe",
            "model": model,
            "started_at": started_at,
            "finished_at": finished_at,
            "responses": self.response_count,
            "continuations": self.continuation_count,
            "tool_calls": self.tool_call_count,
            "function_call_outputs_sent": self.function_call_output_count,
            "item_counts": dict(sorted(self.item_counts.items())),
            "response_status_counts": dict(sorted(self.statuses.items())),
            "response_latencies_ms": self.response_latencies_ms,
            "usage_total": self.usage_total,
            "usage_by_response": self.response_usage,
            "final_message_count": self.final_message_count,
            "final_output_text_bytes": self.final_output_text_bytes,
            "final_output_text_sha256": self.final_output_text_sha256,
        }


def run_probe(
    *,
    output_root: Path,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    prompt: str = (
        "Compare inventory with demand for sku_123. Use the programmatic tool "
        "calling path for the two read-only lookups, run independent lookups "
        "concurrently, and return the computed shortage as a small JSON result."
    ),
    max_responses: int = DEFAULT_MAX_RESPONSES,
    transport: ResponseTransport | None = None,
    implementations: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    if max_responses < 1:
        raise ProbeError("max_responses must be positive")
    output_root.mkdir(parents=True, exist_ok=True)
    output_root.chmod(0o700)
    events_path = output_root / "events.jsonl"
    raw_dir = output_root / "raw-responses"
    request_path = output_root / "request.json"
    trace_path = output_root / "runtime-trace.jsonl"
    trace_summary_path = output_root / "runtime-trace-summary.json"
    metrics_path = output_root / "metrics.json"

    tools = default_tools()
    request_input: list[Mapping[str, Any]] = [
        {"role": "user", "content": prompt},
    ]
    initial_payload = {
        "model": model,
        "store": False,
        "input": request_input,
        "tools": tools,
    }
    _write_json(
        request_path,
        {
            "model": model,
            "store": False,
            "input": request_input,
            "tools": tools,
            "authorization": "omitted",
        },
    )
    if transport is None:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ProbeError("OPENAI_API_KEY is required for a live Responses API probe")
        transport = UrllibResponseTransport(api_key, base_url, DEFAULT_TIMEOUT_SECONDS)
    implementations = implementations or default_implementations()

    started_at = _utc_now()
    accumulator = _ProbeAccumulator()
    event_sequence = 0
    finished = False
    try:
        for _ in range(max_responses):
            payload = {**initial_payload, "input": request_input}
            response, raw_response, latency_ms = transport.create(payload)
            raw_dir.mkdir(parents=True, exist_ok=True)
            raw_path = raw_dir / f"{accumulator.response_count + 1:04d}.json"
            raw_path.write_bytes(raw_response)
            raw_path.chmod(0o600)
            calls = accumulator.record(response, latency_ms)
            event_sequence += 1
            _append_jsonl(
                events_path,
                {
                    "type": "responses.response",
                    "sequence": event_sequence,
                    "response": response,
                },
            )
            request_input.extend(
                item for item in response.get("output", []) if isinstance(item, Mapping)
            )
            if not calls:
                messages = [
                    item
                    for item in response.get("output", [])
                    if isinstance(item, Mapping) and item.get("type") == "message"
                ]
                if messages:
                    finished = True
                    break
                continue
            outputs: list[Mapping[str, Any]] = []
            for call in calls:
                name = call.get("name")
                call_id = call.get("call_id")
                arguments = call.get("arguments", "{}")
                caller = call.get("caller")
                if not isinstance(name, str) or not isinstance(call_id, str):
                    raise ProbeError("function_call is missing name or call_id")
                if not isinstance(arguments, str):
                    raise ProbeError(f"function_call {call_id} has non-string arguments")
                try:
                    parsed_arguments = json.loads(arguments)
                except json.JSONDecodeError as exc:
                    raise ProbeError(f"function_call {call_id} has invalid arguments") from exc
                implementation = implementations.get(name)
                if implementation is None:
                    raise ProbeError(f"no safe probe implementation for function {name}")
                result = implementation(parsed_arguments)
                function_output: dict[str, Any] = {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": json.dumps(result, ensure_ascii=False, sort_keys=True),
                }
                if caller is not None:
                    function_output["caller"] = caller
                outputs.append(function_output)
                event_sequence += 1
                _append_jsonl(
                    events_path,
                    {
                        "type": "function_call_output",
                        "sequence": event_sequence,
                        "item": function_output,
                    },
                )
            accumulator.function_call_output_count += len(outputs)
            request_input.extend(outputs)
        else:
            raise ProbeError(f"probe reached max_responses={max_responses} without a final message")
    except (OSError, TypeError, ValueError) as exc:
        raise ProbeError(str(exc)) from exc

    if not finished:
        raise ProbeError("probe ended without a final message")
    finished_at = _utc_now()
    try:
        trace_summary = capture_runtime_trace(events_path, trace_path, trace_summary_path)
    except TraceCaptureError as exc:
        raise ProbeError(f"required PTC trace handler failed: {exc}") from exc
    metrics = accumulator.public(model=model, started_at=started_at, finished_at=finished_at)
    metrics["request"] = {
        "base_url": base_url,
        "programmatic_tool_calling_enabled": True,
        "eligible_tools": [
            item["name"] for item in tools if item.get("type") == "function" and "name" in item
        ],
        "allowed_callers": {
            item["name"]: item.get("allowed_callers")
            for item in tools
            if item.get("type") == "function" and "name" in item
        },
    }
    metrics["trace"] = {
        "schema_version": trace_summary["schema_version"],
        "marker_presence": trace_summary["marker_presence"],
        "marker_counts": trace_summary["marker_counts"],
        "ptc_caller_graph": trace_summary["ptc_caller_graph"],
        "source": trace_summary["source"],
        "normalized_trace": trace_summary["normalized_trace"],
    }
    _write_json(metrics_path, metrics)
    return metrics


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--prompt", default=None)
    parser.add_argument("--max-responses", type=int, default=DEFAULT_MAX_RESPONSES)
    args = parser.parse_args(argv)
    metrics = run_probe(
        output_root=args.output,
        model=args.model,
        base_url=args.base_url,
        prompt=args.prompt
        or (
            "Compare inventory with demand for sku_123. Use the programmatic tool "
            "calling path for the two read-only lookups, run independent lookups "
            "concurrently, and return the computed shortage as a small JSON result."
        ),
        max_responses=args.max_responses,
    )
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
