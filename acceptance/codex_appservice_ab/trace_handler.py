"""Bounded, structural, metadata-first tracing for Codex JSONL artifacts.

The private Codex event stream remains the source of truth.  This module adds
an independently useful normalized trace for handoff and analysis.  It never
rewrites or truncates the source JSONL, and it does not treat arbitrary prose
as protocol evidence.  Marker detection is limited to typed event/item
objects, typed fields, and code bodies belonging to structurally identified
program items.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TRACE_SCHEMA_VERSION = "vuoro.outctl.codex-runtime-trace/v2"
DEFAULT_MAX_EVENTS = 10_000
DEFAULT_MAX_TRACE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_PER_MARKER = 12
MAX_FIELD_PATHS = 400
MAX_STRING_BYTES = 16 * 1024
MAX_GRAPH_NODES = 10_000

MARKER_NAMES = (
    "custom_tool_call",
    "custom_tool_call_output",
    "code_mode_only",
    "ptc",
    "ptc_config",
    "ptc_caller_linkage",
    "program_item",
    "program_output",
    "program_call",
    "function_call",
    "function_call_output",
    "exec_envelope",
    "exec_tool",
    "promise_all",
)

TRANSPORT_MARKERS = (
    "custom_tool_call",
    "custom_tool_call_output",
    "code_mode_only",
    "exec_envelope",
    "ptc_config",
)
PTC_MARKERS = (
    "ptc",
    "ptc_caller_linkage",
    "program_item",
    "program_output",
    "program_call",
    "function_call",
    "function_call_output",
)
BEHAVIOR_MARKERS = ("exec_tool", "promise_all")

_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(\b(?:sk|rk)-)[A-Za-z0-9_-]{16,}"),
    re.compile(
        r"(?i)(\b(?:api[_-]?key|token|password|secret|private[_-]?key)\b\s*[:=]\s*)"
        r"[^\s,;]+"
    ),
)
_TOOL_CALL_RE = re.compile(r"\btools\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PROMISE_ALL_RE = re.compile(r"\bPromise\s*\.\s*all\s*\(", re.IGNORECASE)
_SAFE_METADATA_KEYS = {
    "cached_input_tokens",
    "cache_write_input_tokens",
    "count",
    "duration_ms",
    "exit_code",
    "input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "size",
    "status",
    "success",
    "total",
    "truncated",
}


class TraceCaptureError(RuntimeError):
    """Raised when the required trace handler cannot write its artifacts."""


@dataclass(frozen=True)
class _NodeRef:
    call_id: str
    source_line: int
    path: str
    caller_type: str | None = None
    caller_id: str | None = None


@dataclass
class _GraphState:
    programs: dict[str, list[_NodeRef]] = field(default_factory=lambda: defaultdict(list))
    nested_calls: dict[str, list[_NodeRef]] = field(default_factory=lambda: defaultdict(list))
    function_calls: dict[str, list[_NodeRef]] = field(default_factory=lambda: defaultdict(list))
    function_outputs: dict[str, list[_NodeRef]] = field(default_factory=lambda: defaultdict(list))
    program_outputs: dict[str, list[_NodeRef]] = field(default_factory=lambda: defaultdict(list))
    stored_nodes: int = 0
    truncated: bool = False

    def add(self, target: dict[str, list[_NodeRef]], key: str, ref: _NodeRef) -> None:
        if self.stored_nodes >= MAX_GRAPH_NODES:
            self.truncated = True
            return
        target[key].append(ref)
        self.stored_nodes += 1


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _redact_text(value: str, exact_redactions: Sequence[str]) -> str:
    result = value
    for secret in exact_redactions:
        if secret:
            result = result.replace(secret, "[REDACTED]")
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    return result


def _bounded_text(
    value: str, exact_redactions: Sequence[str], limit: int = MAX_STRING_BYTES
) -> str:
    result = _redact_text(value, exact_redactions)
    encoded = result.encode("utf-8")
    if len(encoded) <= limit:
        return result
    return encoded[:limit].decode("utf-8", errors="ignore") + "…[TRUNCATED]"


def _path_text(parts: Sequence[str | int]) -> str:
    result = "$"
    for part in parts:
        if isinstance(part, int):
            result += f"[{part}]"
        else:
            result += f"[{json.dumps(part, ensure_ascii=False)}]"
    return result


def _iter_structural_objects(
    value: Any, path: tuple[str | int, ...] = ()
) -> Iterable[tuple[str, Mapping[str, Any]]]:
    """Yield mappings and their paths without inspecting arbitrary strings."""
    if isinstance(value, Mapping):
        yield _path_text(path), value
        for key, item in value.items():
            yield from _iter_structural_objects(item, (*path, str(key)))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            yield from _iter_structural_objects(item, (*path, index))


def _iter_keys(value: Any, path: tuple[str | int, ...] = ()) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield _path_text((*path, str(key)))
            yield from _iter_keys(item, (*path, str(key)))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            yield from _iter_keys(item, (*path, index))


def _values_for_key(value: Any, wanted: set[str]) -> list[str]:
    """Extract only direct scalar/list values for named structural keys."""
    found: list[str] = []

    def visit(current: Any) -> None:
        if isinstance(current, Mapping):
            for key, item in current.items():
                if str(key).casefold() in wanted:
                    if isinstance(item, str):
                        found.append(item)
                    elif isinstance(item, Sequence) and not isinstance(
                        item, (str, bytes, bytearray)
                    ):
                        found.extend(str(value) for value in item if isinstance(value, str))
                visit(item)
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            for item in current:
                visit(item)

    visit(value)
    return found


def _event_type(event: Mapping[str, Any]) -> str | None:
    candidates: list[Any] = [event]
    item = event.get("item")
    if isinstance(item, Mapping):
        candidates.append(item)
    params = event.get("params")
    if isinstance(params, Mapping):
        candidates.append(params)
        raw_item = params.get("item")
        if isinstance(raw_item, Mapping):
            candidates.append(raw_item)
    for candidate in candidates:
        if isinstance(candidate, Mapping) and isinstance(candidate.get("type"), str):
            return str(candidate["type"])
    return None


def _event_name(event: Mapping[str, Any], exact_redactions: Sequence[str]) -> str | None:
    candidates: list[Any] = [event, event.get("item")]
    params = event.get("params")
    if isinstance(params, Mapping):
        candidates.extend((params, params.get("item")))
    for candidate in candidates:
        if isinstance(candidate, Mapping) and isinstance(candidate.get("name"), str):
            return _bounded_text(str(candidate["name"]), exact_redactions, limit=512)
    return None


def _object_type(value: Mapping[str, Any]) -> str | None:
    raw = value.get("type")
    return raw.casefold() if isinstance(raw, str) else None


def _string_field(value: Mapping[str, Any], key: str) -> str | None:
    raw = value.get(key)
    return raw if isinstance(raw, str) and raw else None


def _is_response_item_boundary(path: str) -> bool:
    """Accept only known event/item boundaries for protocol markers."""
    if path == "$" or path in {
        '$["item"]',
        '$["params"]["item"]',
        '$["program"]',
        '$["params"]["program"]',
    }:
        return True
    return bool(
        re.fullmatch(
            r'\$(?:\["params"\]|\["response"\])?\["output"\]\[\d+\]',
            path,
        )
    )


def _caller_link(value: Mapping[str, Any]) -> tuple[str | None, str | None]:
    raw = value.get("caller")
    if isinstance(raw, Mapping):
        caller_type = _string_field(raw, "type")
        caller_id = _string_field(raw, "caller_id")
        return caller_type.casefold() if caller_type else None, caller_id
    if isinstance(raw, str) and raw:
        # Legacy/transport shorthand is retained as a value but cannot prove
        # a caller graph without a caller_id.
        return raw.casefold(), None
    return None, None


def _caller_links(event: Mapping[str, Any]) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    for path, value in _iter_structural_objects(event):
        caller_type, caller_id = _caller_link(value)
        if caller_type is None and caller_id is None:
            continue
        link: dict[str, str] = {"path": path, "type": caller_type or "unknown"}
        if caller_id is not None:
            link["caller_id"] = caller_id
        links.append(link)
    return links[:32]


def _program_bodies(event: Mapping[str, Any]) -> list[tuple[str, str]]:
    bodies: list[tuple[str, str]] = []
    seen: set[str] = set()
    for path, value in _iter_structural_objects(event):
        object_type = _object_type(value)
        is_program = (
            _is_response_item_boundary(path)
            and object_type in {"program", "program_call"}
        )
        code = value.get("code")
        # Codex app-server raw events expose Code Mode as a custom ``exec``
        # call whose generated JavaScript is carried in ``input`` rather than
        # as a Responses ``program`` item.  The type/name pair is the
        # structural boundary that makes inspecting this string safe.
        if (
            _is_response_item_boundary(path)
            and
            object_type == "custom_tool_call"
            and _string_field(value, "name") == "exec"
            and isinstance(value.get("input"), str)
        ):
            is_program = True
            code = value["input"]
            path = path + '["input"]'
        if is_program and isinstance(code, str) and path not in seen:
            bodies.append((path, code))
            seen.add(path)
    return bodies


def _hit(marker: str, path: str, value: str) -> dict[str, str]:
    return {"marker": marker, "path": path, "value": value}


def _structural_evidence(
    event: Mapping[str, Any], exact_redactions: Sequence[str]
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Classify typed protocol objects and program behavior only."""
    del exact_redactions  # No arbitrary event/code text is copied to evidence.
    hits: list[dict[str, str]] = []
    called_tools: set[str] = set()
    programs_using_tools: Counter[str] = Counter()
    tool_invocations: Counter[str] = Counter()
    program_bodies: list[dict[str, Any]] = []
    uses_promise_all = False
    programs_using_promise_all = 0

    for path, value in _iter_structural_objects(event):
        object_type = _object_type(value)
        is_item = _is_response_item_boundary(path)
        if is_item and object_type == "custom_tool_call":
            hits.append(_hit("custom_tool_call", path + '["type"]', "custom_tool_call"))
            if _string_field(value, "name") == "exec":
                hits.append(_hit("exec_envelope", path + '["name"]', "exec"))
        elif is_item and object_type == "custom_tool_call_output":
            hits.append(
                _hit(
                    "custom_tool_call_output",
                    path + '["type"]',
                    "custom_tool_call_output",
                )
            )
        elif is_item and object_type == "program":
            hits.append(_hit("program_item", path + '["type"]', "program"))
            hits.append(_hit("ptc", path + '["type"]', "program"))
        elif is_item and object_type == "program_call":
            hits.append(_hit("program_call", path + '["type"]', "program_call"))
            hits.append(_hit("ptc", path + '["type"]', "program_call"))
        elif is_item and object_type == "program_output":
            hits.append(_hit("program_output", path + '["type"]', "program_output"))
            hits.append(_hit("ptc", path + '["type"]', "program_output"))
        elif is_item and object_type == "function_call":
            hits.append(_hit("function_call", path + '["type"]', "function_call"))
            hits.append(_hit("ptc", path + '["type"]', "function_call"))
        elif is_item and object_type == "function_call_output":
            hits.append(
                _hit("function_call_output", path + '["type"]', "function_call_output")
            )
            hits.append(_hit("ptc", path + '["type"]', "function_call_output"))

        for key, item in value.items():
            folded_key = str(key).casefold()
            field_path = path + f"[{json.dumps(str(key), ensure_ascii=False)}]"
            if is_item and folded_key == "code_mode_only" and item is True:
                hits.append(_hit("code_mode_only", field_path, "true"))
            elif is_item and folded_key in {
                "programmatic_tool_calling",
                "programmatic-tool-calling",
            }:
                hits.append(_hit("ptc_config", field_path, "present"))
                hits.append(_hit("ptc", field_path, "configuration"))

    for path, code in _program_bodies(event):
        tool_counts = Counter(_TOOL_CALL_RE.findall(code))
        tools = sorted(tool_counts)
        called_tools.update(tools)
        programs_using_tools.update(tools)
        tool_invocations.update(tool_counts)
        has_promise_all = bool(_PROMISE_ALL_RE.search(code))
        uses_promise_all = uses_promise_all or has_promise_all
        if has_promise_all:
            programs_using_promise_all += 1
        body_evidence: dict[str, Any] = {
            "path": path,
            "code_sha256": _sha256_bytes(code.encode("utf-8")),
            "code_bytes": len(code.encode("utf-8")),
            "called_tools": tools,
            "tool_invocation_counts": dict(sorted(tool_counts.items())),
            "tool_invocation_total": sum(tool_counts.values()),
            "uses_promise_all": has_promise_all,
        }
        program_bodies.append(body_evidence)
        for tool in tools:
            if tool == "exec_command":
                hits.append(_hit("exec_tool", path + '["code"]', "tools.exec_command"))
        if has_promise_all:
            hits.append(_hit("promise_all", path + '["code"]', "Promise.all"))

    return hits, {
        "called_tools": sorted(called_tools),
        "programs_using_tools": dict(sorted(programs_using_tools.items())),
        "tool_invocations": dict(sorted(tool_invocations.items())),
        "programs_using_promise_all": programs_using_promise_all,
        "program_bodies": program_bodies[:32],
        "uses_promise_all": uses_promise_all,
    }


def _safe_metadata(event: Mapping[str, Any], exact_redactions: Sequence[str]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for path, value in _iter_structural_objects(event):
        for key, item in value.items():
            folded_key = str(key).casefold()
            if folded_key not in _SAFE_METADATA_KEYS:
                continue
            if isinstance(item, (str, bool, int, float)):
                safe_item: Any = (
                    _bounded_text(item, exact_redactions, limit=512)
                    if isinstance(item, str)
                    else item
                )
                metadata[path + f"[{json.dumps(str(key), ensure_ascii=False)}]"] = safe_item
    return dict(list(metadata.items())[:128])


def _node_ref(path: str, value: Mapping[str, Any], source_line: int) -> _NodeRef | None:
    call_id = _string_field(value, "call_id")
    if call_id is None:
        return None
    caller_type, caller_id = _caller_link(value)
    return _NodeRef(
        call_id=call_id,
        source_line=source_line,
        path=path,
        caller_type=caller_type,
        caller_id=caller_id,
    )


def _iter_graph_objects(
    value: Any,
    path: tuple[str | int, ...] = (),
    inherited_call_id: str | None = None,
) -> Iterable[tuple[str, Mapping[str, Any], str | None]]:
    """Yield structural objects with an enclosing call ID as a safe fallback."""
    if isinstance(value, Mapping):
        current_call_id = _string_field(value, "call_id") or inherited_call_id
        yield _path_text(path), value, current_call_id
        for key, item in value.items():
            yield from _iter_graph_objects(item, (*path, str(key)), current_call_id)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            yield from _iter_graph_objects(item, (*path, index), inherited_call_id)


def _update_graph(state: _GraphState, event: Mapping[str, Any], source_line: int) -> None:
    for path, value, inherited_call_id in _iter_graph_objects(event):
        if path.endswith('["caller"]'):
            continue
        object_type = _object_type(value)
        if object_type not in {
            "program",
            "program_call",
            "function_call",
            "function_call_output",
            "program_output",
        }:
            continue
        ref = _node_ref(path, value, source_line)
        if (
            ref is None
            and object_type in {"program", "program_call"}
            and inherited_call_id is not None
        ):
            ref = _NodeRef(
                call_id=inherited_call_id,
                source_line=source_line,
                path=path,
            )
        if ref is None:
            continue
        if object_type in {"program", "program_call"}:
            state.add(state.programs, ref.call_id, ref)
        elif object_type == "function_call":
            state.add(state.function_calls, ref.call_id, ref)
            if ref.caller_type == "program" and ref.caller_id:
                state.add(state.nested_calls, ref.caller_id, ref)
        elif object_type == "function_call_output":
            state.add(state.function_outputs, ref.call_id, ref)
        elif object_type == "program_output":
            state.add(state.program_outputs, ref.call_id, ref)


def _same_caller(left: _NodeRef, right: _NodeRef) -> bool:
    return (
        left.caller_type is not None
        and left.caller_id is not None
        and left.caller_type == right.caller_type
        and left.caller_id == right.caller_id
    )


def _ref_public(value: _NodeRef) -> dict[str, Any]:
    result: dict[str, Any] = {
        "call_id": value.call_id,
        "source_line": value.source_line,
        "path": value.path,
    }
    if value.caller_type is not None:
        result["caller_type"] = value.caller_type
    if value.caller_id is not None:
        result["caller_id"] = value.caller_id
    return result


def _finalize_graph(state: _GraphState) -> dict[str, Any]:
    linked_programs: list[dict[str, Any]] = []
    orphan_nested_calls: list[dict[str, Any]] = []
    orphan_program_outputs: list[dict[str, Any]] = []
    orphan_function_outputs: list[dict[str, Any]] = []
    programs_without_output: list[dict[str, Any]] = []

    for program_id, program_refs in state.programs.items():
        nested = state.nested_calls.get(program_id, [])
        program_outputs = state.program_outputs.get(program_id, [])
        child_records: list[dict[str, Any]] = []
        program_valid = bool(nested) and bool(program_outputs)
        for child in nested:
            matching_outputs = [
                output
                for output in state.function_outputs.get(child.call_id, [])
                if _same_caller(child, output)
            ]
            child_valid = bool(matching_outputs)
            program_valid = program_valid and child_valid
            child_record = {
                "function_call": _ref_public(child),
                "function_call_outputs": [_ref_public(item) for item in matching_outputs[:8]],
                "caller_linkage_valid": child_valid,
            }
            child_records.append(child_record)
            if not child_valid:
                orphan_nested_calls.append(_ref_public(child))
                if state.function_outputs.get(child.call_id):
                    orphan_function_outputs.extend(
                        _ref_public(item) for item in state.function_outputs[child.call_id][:8]
                    )
        if not program_outputs:
            program_valid = False
            programs_without_output.extend(_ref_public(item) for item in program_refs[:8])
        if program_valid:
            linked_programs.append(
                {
                    "program": _ref_public(program_refs[0]),
                    "nested_calls": child_records,
                    "program_outputs": [_ref_public(item) for item in program_outputs[:8]],
                    "caller_linkage_valid": True,
                }
            )

    known_program_ids = set(state.programs)
    for program_id, refs in state.nested_calls.items():
        if program_id not in known_program_ids:
            orphan_nested_calls.extend(_ref_public(item) for item in refs[:8])
    for program_id, refs in state.program_outputs.items():
        if program_id not in known_program_ids:
            orphan_program_outputs.extend(_ref_public(item) for item in refs[:8])
    known_function_ids = set(state.function_calls)
    for function_id, refs in state.function_outputs.items():
        if function_id not in known_function_ids:
            orphan_function_outputs.extend(_ref_public(item) for item in refs[:8])

    orphan_nested_calls = orphan_nested_calls[:64]
    orphan_program_outputs = orphan_program_outputs[:64]
    orphan_function_outputs = orphan_function_outputs[:64]
    programs_without_output = programs_without_output[:64]
    observed_programs = bool(state.programs)
    return {
        "graph_schema_version": "vuoro.outctl.ptc-caller-graph/v1",
        "observed_programs": len(state.programs),
        "linked_programs": linked_programs[:64],
        "orphan_nested_calls": orphan_nested_calls,
        "orphan_program_outputs": orphan_program_outputs,
        "orphan_function_call_outputs": orphan_function_outputs,
        "programs_without_output": programs_without_output,
        "caller_linkage_valid": bool(
            observed_programs
            and linked_programs
            and not orphan_nested_calls
            and not orphan_program_outputs
            and not orphan_function_outputs
            and not programs_without_output
            and not state.truncated
        ),
        "graph_truncated": state.truncated,
        "graph_nodes_stored": state.stored_nodes,
        "graph_node_limit": MAX_GRAPH_NODES,
    }


def _event_record(
    event: Mapping[str, Any],
    *,
    source_line: int,
    exact_redactions: Sequence[str],
) -> dict[str, Any]:
    canonical = _canonical_json(event)
    hits, behavior = _structural_evidence(event, exact_redactions)
    fields = list(dict.fromkeys(_iter_keys(event)))[:MAX_FIELD_PATHS]
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "source_line": source_line,
        "event_type": _event_type(event),
        "event_name": _event_name(event, exact_redactions),
        "event_sha256": _sha256_bytes(canonical),
        "event_bytes": len(canonical),
        "field_paths": fields,
        "markers": hits,
        "call_ids": _values_for_key(event, {"call_id"})[:32],
        "caller_values": _values_for_key(event, {"caller", "allowed_callers"})[:32],
        "caller_links": _caller_links(event),
        "safe_metadata": _safe_metadata(event, exact_redactions),
        "program_behavior": behavior,
    }


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def capture_runtime_trace(
    source_path: Path,
    trace_path: Path,
    summary_path: Path,
    *,
    exact_redactions: Sequence[str] = (),
    max_events: int = DEFAULT_MAX_EVENTS,
    max_trace_bytes: int = DEFAULT_MAX_TRACE_BYTES,
) -> dict[str, Any]:
    """Capture structural normalized evidence while preserving source JSONL."""
    if max_events < 1:
        raise TraceCaptureError("max_events must be positive")
    if max_trace_bytes < 1:
        raise TraceCaptureError("max_trace_bytes must be positive")
    if not source_path.is_file():
        raise TraceCaptureError(f"source JSONL is missing: {source_path}")
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    source_hash = hashlib.sha256()
    source_bytes = 0
    source_lines = 0
    parsed_events = 0
    invalid_lines: list[dict[str, Any]] = []
    event_type_counts: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()
    domain_counts: dict[str, Counter[str]] = {
        "codex_transport": Counter(),
        "openai_ptc_semantics": Counter(),
        "program_behavior": Counter(),
    }
    called_tools: Counter[str] = Counter()
    programs_using_tools: Counter[str] = Counter()
    tool_invocations: Counter[str] = Counter()
    programs_using_promise_all = 0
    evidence: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    graph = _GraphState()
    trace_events_written = 0
    trace_bytes_written = 0
    trace_truncated = False

    try:
        with source_path.open("rb") as source, trace_path.open("wb") as trace:
            trace_path.chmod(0o600)
            for raw_line in source:
                source_hash.update(raw_line)
                source_bytes += len(raw_line)
                source_lines += 1
                if not raw_line.strip():
                    continue
                try:
                    value = json.loads(raw_line.decode("utf-8", errors="replace"))
                except json.JSONDecodeError as exc:
                    invalid_lines.append({"line": source_lines, "error": str(exc)[:300]})
                    continue
                if not isinstance(value, Mapping):
                    invalid_lines.append(
                        {"line": source_lines, "error": "JSON value is not an object"}
                    )
                    continue
                parsed_events += 1
                event_type = _event_type(value)
                if event_type is not None:
                    event_type_counts[event_type] += 1
                record = _event_record(
                    value,
                    source_line=source_lines,
                    exact_redactions=exact_redactions,
                )
                _update_graph(graph, value, source_lines)
                for tool in record["program_behavior"]["called_tools"]:
                    called_tools[tool] += 1
                for tool, count in record["program_behavior"]["programs_using_tools"].items():
                    programs_using_tools[tool] += int(count)
                for tool, count in record["program_behavior"]["tool_invocations"].items():
                    tool_invocations[tool] += int(count)
                programs_using_promise_all += int(
                    record["program_behavior"]["programs_using_promise_all"]
                )
                for hit in record["markers"]:
                    marker = str(hit["marker"])
                    marker_counts[marker] += 1
                    if marker in TRANSPORT_MARKERS:
                        domain_counts["codex_transport"][marker] += 1
                    elif marker in PTC_MARKERS:
                        domain_counts["openai_ptc_semantics"][marker] += 1
                    elif marker in BEHAVIOR_MARKERS:
                        domain_counts["program_behavior"][marker] += 1
                    if len(evidence[marker]) < MAX_EVIDENCE_PER_MARKER:
                        evidence[marker].append(
                            {
                                "source_line": source_lines,
                                "event_type": record["event_type"],
                                "event_sha256": record["event_sha256"],
                                "path": hit["path"],
                                "value": hit["value"],
                            }
                        )
                encoded = _canonical_json(record) + b"\n"
                if (
                    trace_events_written < max_events
                    and trace_bytes_written + len(encoded) <= max_trace_bytes
                ):
                    trace.write(encoded)
                    trace_events_written += 1
                    trace_bytes_written += len(encoded)
                else:
                    trace_truncated = True
    except OSError as exc:
        raise TraceCaptureError(str(exc)) from exc

    ptc_graph = _finalize_graph(graph)
    if ptc_graph["linked_programs"]:
        marker_counts["ptc_caller_linkage"] = len(ptc_graph["linked_programs"])
        domain_counts["openai_ptc_semantics"]["ptc_caller_linkage"] = len(
            ptc_graph["linked_programs"]
        )
        evidence["ptc_caller_linkage"].extend(
            {
                "source_line": item["program"]["source_line"],
                "event_type": "program",
                "event_sha256": "",
                "path": item["program"]["path"],
                "value": "validated caller/call_id graph",
            }
            for item in ptc_graph["linked_programs"][:MAX_EVIDENCE_PER_MARKER]
        )

    marker_presence = {marker: marker in marker_counts for marker in MARKER_NAMES}
    summary: dict[str, Any] = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "handler": "acceptance/codex_appservice_ab/trace_handler.py",
        "handler_status": "complete",
        "captured_at": _utc_now(),
        "normalized_payload_policy": {
            "mode": "metadata_only",
            "raw_event_bodies_included": False,
            "program_code_included": False,
            "program_code_represented_by": [
                "sha256",
                "bytes",
                "called_tools",
                "uses_promise_all",
            ],
        },
        "source": {
            "file": source_path.name,
            "sha256": source_hash.hexdigest(),
            "bytes": source_bytes,
            "lines": source_lines,
            "raw_preserved": True,
        },
        "parsed_events": parsed_events,
        "invalid_lines": invalid_lines[:64],
        "invalid_line_count": len(invalid_lines),
        "normalized_trace": {
            "file": trace_path.name,
            "sha256": _sha256_file(trace_path),
            "bytes": trace_bytes_written,
            "events_written": trace_events_written,
            "max_events": max_events,
            "max_bytes": max_trace_bytes,
            "truncated": trace_truncated,
        },
        "event_type_counts": dict(sorted(event_type_counts.items())),
        "marker_counts": dict(sorted(marker_counts.items())),
        "observed_markers": sorted(marker_counts),
        "marker_presence": marker_presence,
        "evidence_domains": {
            domain: {"marker_counts": dict(sorted(counts.items()))}
            for domain, counts in domain_counts.items()
        },
        "evidence_domains_extra": {
            "program_behavior": {
                "called_tools": dict(sorted(called_tools.items())),
                "programs_using_tools": dict(sorted(programs_using_tools.items())),
                "tool_invocations": dict(sorted(tool_invocations.items())),
                "programs_using_promise_all": programs_using_promise_all,
            }
        },
        "ptc_caller_graph": ptc_graph,
        "evidence": dict(sorted(evidence.items())),
        "observability_limits": [
            (
                "absence means the marker was not exposed in the captured JSONL; "
                "it does not prove the runtime did not use an internal mechanism"
            ),
            (
                "lexical terms in arbitrary prose, logs, command output, and messages "
                "are not protocol evidence"
            ),
            "post-truncation model history bytes/tokens are not inferred from command output",
            "raw source JSONL is private and must not be copied into ordinary model-facing output",
        ],
    }
    try:
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        summary_path.chmod(0o600)
    except OSError as exc:
        raise TraceCaptureError(str(exc)) from exc
    return summary


def _parse_exact_redactions(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--exact-redaction-json must be valid JSON: {exc}") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) and item for item in parsed):
        raise SystemExit("--exact-redaction-json must be a JSON string array")
    return tuple(parsed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="private Codex events.jsonl")
    parser.add_argument("--trace", type=Path, required=True, help="normalized trace JSONL")
    parser.add_argument("--summary", type=Path, required=True, help="trace summary JSON")
    parser.add_argument("--exact-redaction-json")
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_TRACE_BYTES)
    args = parser.parse_args(argv)
    summary = capture_runtime_trace(
        args.source,
        args.trace,
        args.summary,
        exact_redactions=_parse_exact_redactions(args.exact_redaction_json),
        max_events=args.max_events,
        max_trace_bytes=args.max_bytes,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
