"""Bounded agent telemetry and deterministic experiment reporting.

This module deliberately keeps collection independent from any deployment.  A
runner can append structured events locally, export Prometheus samples, or send
the same events to an OpenTelemetry Collector/Loki endpoint when appservice
provides one.  Run and session identifiers are event attributes only; they are
never Prometheus labels.
"""

from __future__ import annotations

import json
import math
import statistics
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from outctl.serialization import canonical_json_text, sha256_hex

OBSERVABILITY_SCHEMA = "vuoro.outctl.observability.event/v1"
REPORT_SCHEMA = "vuoro.outctl.experiment-report/v1"

# These values become Prometheus labels.  Keep this list intentionally small:
# run/session/conversation/tool/correlation identifiers belong in log records.
PROMETHEUS_LABELS = ("experiment", "arm", "provider", "model", "harness", "scenario")
PROMETHEUS_RESULT_LABEL = "result"
_EVENTS = {
    "run_started",
    "model_request",
    "model_response",
    "tool_call",
    "tool_result",
    "run_completed",
}
_RESULTS = {"pass", "fail", "error", "unknown"}
_FORBIDDEN_KEYS = {
    "prompt",
    "response",
    "body",
    "content",
    "raw",
    "stdout",
    "stderr",
    "transcript",
    "credential",
    "secret",
}
_METRIC_ALIASES = {
    "tokens.input": "input_tokens",
    "tokens.output": "output_tokens",
    "tokens.cached": "cached_tokens",
    "tokens.cache_write": "cache_write_tokens",
    "cost": "cost_usd",
    "duration": "duration_seconds",
    "outcome": "outcome",
    "model_requests": "model_requests",
    "tool_calls": "tool_calls",
    "tool_failures": "tool_failures",
    "active_time": "active_seconds",
    "lines_changed": "lines_changed",
    "evidence_bytes_visible": "evidence_bytes_visible",
    "tool_visible_bytes": "evidence_bytes_visible",
    "tool_latency": "tool_latency_seconds",
}
_DERIVED = {
    "model_decision_boundaries",
    "tools_per_model_round",
    "tokens_per_success",
    "cost_per_success",
    "evidence_bytes_visible",
    "interaction_topology",
}


class ObservabilityError(ValueError):
    """Raised for malformed, unsafe, or semantically incomplete telemetry."""


class EventSink(Protocol):
    """Minimal sink interface used by :class:`TelemetryRecorder`."""

    def emit(self, event: Mapping[str, Any]) -> None:
        """Accept one already-validated event."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _label(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ObservabilityError(f"{name} must be a non-empty string of at most 128 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ObservabilityError(f"{name} contains a control character")
    return value


def _optional_label(value: object, name: str) -> str | None:
    return None if value is None else _label(value, name)


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ObservabilityError(
            f"{name} must be a non-empty identifier of at most 256 characters"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ObservabilityError(f"{name} contains a control character")
    return value


def _nonnegative(value: object, name: str, *, integral: bool = True) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        kind = "integer" if integral else "number"
        raise ObservabilityError(f"{name} must be a non-negative {kind}")
    if (integral and not isinstance(value, int)) or value < 0:
        kind = "integer" if integral else "number"
        raise ObservabilityError(f"{name} must be a non-negative {kind}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ObservabilityError(f"{name} must be finite")
    return value


def _safe_attributes(value: object) -> dict[str, str | int | float | bool | None]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ObservabilityError("attributes must be an object")
    result: dict[str, str | int | float | bool | None] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ObservabilityError(
                "attribute keys must be non-empty strings of at most 64 characters"
            )
        if key.casefold() in _FORBIDDEN_KEYS or any(
            forbidden in key.casefold() for forbidden in ("prompt", "response", "secret", "token")
        ):
            raise ObservabilityError(f"raw or sensitive attribute is forbidden: {key}")
        if not isinstance(item, (str, int, float, bool)) and item is not None:
            raise ObservabilityError(f"attribute {key} must be a scalar")
        if isinstance(item, float) and not math.isfinite(item):
            raise ObservabilityError(f"attribute {key} must be finite")
        if isinstance(item, str) and len(item) > 512:
            raise ObservabilityError(f"attribute {key} exceeds the 512 character bound")
        result[key] = item
    return result


@dataclass(frozen=True)
class TelemetryContext:
    """Correlation data for one run.

    Only the bounded analysis dimensions returned by :meth:`labels` are
    eligible for Prometheus labels.  The identifiers remain available in Loki
    and OTLP log records for sequence reconstruction.
    """

    experiment: str
    arm: str
    run_id: str
    session_id: str
    provider: str | None = None
    model: str | None = None
    harness: str | None = None
    scenario: str | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("experiment", "arm"):
            _label(getattr(self, name), name)
        for name in ("run_id", "session_id"):
            _identifier(getattr(self, name), name)
        for name in ("provider", "model", "harness", "scenario"):
            _optional_label(getattr(self, name), name)
        if self.correlation_id is not None:
            _identifier(self.correlation_id, "correlation_id")

    def labels(self) -> dict[str, str]:
        return {
            name: value
            for name in PROMETHEUS_LABELS
            if (value := getattr(self, name)) is not None
        }


@dataclass(frozen=True)
class TelemetryEvent:
    """Validated structured event suitable for local JSONL, Loki, or OTLP."""

    context: TelemetryContext
    event: str
    sequence: int
    occurred_at: str
    fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.event, str) or self.event not in _EVENTS:
            raise ObservabilityError(f"unsupported telemetry event: {self.event}")
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 0
        ):
            raise ObservabilityError("sequence must be a non-negative integer")
        if not isinstance(self.occurred_at, str) or not self.occurred_at:
            raise ObservabilityError("occurred_at must be a non-empty timestamp")
        _validate_fields(self.event, self.fields)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": OBSERVABILITY_SCHEMA,
            "occurred_at": self.occurred_at,
            "event": self.event,
            "experiment": self.context.experiment,
            "arm": self.context.arm,
            "run_id": self.context.run_id,
            "session_id": self.context.session_id,
            "sequence": self.sequence,
        }
        for name in ("provider", "model", "harness", "scenario", "correlation_id"):
            value = getattr(self.context, name)
            if value is not None:
                result[name] = value
        result.update(self.fields)
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> TelemetryEvent:
        if value.get("schema_version") != OBSERVABILITY_SCHEMA:
            raise ObservabilityError("unsupported observability event schema")
        context = TelemetryContext(
            experiment=_required_string(value, "experiment"),
            arm=_required_string(value, "arm"),
            run_id=_required_string(value, "run_id"),
            session_id=_required_string(value, "session_id"),
            provider=value.get("provider"),
            model=value.get("model"),
            harness=value.get("harness"),
            scenario=value.get("scenario"),
            correlation_id=value.get("correlation_id"),
        )
        reserved = {
            "schema_version",
            "occurred_at",
            "event",
            "experiment",
            "arm",
            "run_id",
            "session_id",
            "sequence",
            "provider",
            "model",
            "harness",
            "scenario",
            "correlation_id",
        }
        fields = {key: item for key, item in value.items() if key not in reserved}
        return cls(
            context=context,
            event=_required_string(value, "event"),
            sequence=_required_int(value, "sequence"),
            occurred_at=_required_string(value, "occurred_at"),
            fields=fields,
        )


def _required_string(value: Mapping[str, Any], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item:
        raise ObservabilityError(f"{name} is required")
    return item


def _required_int(value: Mapping[str, Any], name: str) -> int:
    item = value.get(name)
    if not isinstance(item, int) or isinstance(item, bool):
        raise ObservabilityError(f"{name} must be an integer")
    return item


def _validate_fields(event: str, fields: Mapping[str, Any]) -> None:
    if not isinstance(fields, Mapping):
        raise ObservabilityError("event fields must be an object")
    allowed = {
        "tool",
        "duration_ms",
        "active_time_ms",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "cache_write_tokens",
        "cost_usd",
        "output_bytes",
        "visible_bytes",
        "lines_changed",
        "success",
        "result",
        "measurements",
        "attributes",
    }
    unknown = sorted(set(fields) - allowed)
    if unknown:
        raise ObservabilityError(f"unsupported telemetry fields: {', '.join(unknown)}")
    if event in {"tool_call", "tool_result"} and "tool" in fields:
        _label(fields["tool"], "tool")
    for name in (
        "duration_ms",
        "active_time_ms",
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "cache_write_tokens",
        "output_bytes",
        "visible_bytes",
        "lines_changed",
    ):
        if name in fields:
            _nonnegative(fields[name], name)
    if "cost_usd" in fields:
        _nonnegative(fields["cost_usd"], "cost_usd", integral=False)
    if "success" in fields and not isinstance(fields["success"], bool):
        raise ObservabilityError("success must be boolean")
    if "result" in fields and (
        not isinstance(fields["result"], str) or fields["result"] not in _RESULTS
    ):
        raise ObservabilityError("result must be pass, fail, error, or unknown")
    if "measurements" in fields:
        measurements = fields["measurements"]
        if not isinstance(measurements, Mapping):
            raise ObservabilityError("measurements must be an object")
        for name, value in measurements.items():
            if not isinstance(name, str) or not name or name not in _METRIC_ALIASES:
                raise ObservabilityError(f"unsupported measurement: {name}")
            _nonnegative(value, f"measurements.{name}", integral=False)
    if "attributes" in fields:
        _safe_attributes(fields["attributes"])


class JsonlEventSink:
    """Append validated events to a mode-restricted local JSONL file."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        self._file = path.open("a", encoding="utf-8")
        path.chmod(0o600)

    def emit(self, event: Mapping[str, Any]) -> None:
        self._file.write(canonical_json_text(dict(event)) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> JsonlEventSink:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class TelemetryRecorder:
    """Create ordered events for one run and fan them out to local sinks."""

    def __init__(
        self,
        context: TelemetryContext,
        sinks: Sequence[EventSink] = (),
        *,
        clock: Any = _utc_now,
    ) -> None:
        self.context = context
        self.sinks = tuple(sinks)
        self._clock = clock
        self._sequence = 0

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        item = TelemetryEvent(
            context=self.context,
            event=event,
            sequence=self._sequence,
            occurred_at=self._clock(),
            fields=dict(fields),
        )
        self._sequence += 1
        value = item.to_dict()
        for sink in self.sinks:
            sink.emit(value)
        return value

    def run_started(self) -> dict[str, Any]:
        return self.record("run_started")

    def model_request(self, **fields: Any) -> dict[str, Any]:
        return self.record("model_request", **fields)

    def model_response(self, **fields: Any) -> dict[str, Any]:
        return self.record("model_response", **fields)

    def tool_call(self, *, tool: str, **fields: Any) -> dict[str, Any]:
        return self.record("tool_call", tool=tool, **fields)

    def tool_result(self, *, tool: str, **fields: Any) -> dict[str, Any]:
        return self.record("tool_result", tool=tool, **fields)

    def run_completed(self, *, result: str = "unknown", **fields: Any) -> dict[str, Any]:
        return self.record("run_completed", result=result, **fields)


def events_from_pilot_report(
    report: Mapping[str, Any],
    *,
    experiment_id: str,
    baseline_session: str = "B",
    treatment_session: str = "A",
    provider: str = "unknown",
    model: str = "unknown",
    harness: str = "codex",
    scenario: str = "pilot",
    occurred_at: str | None = None,
) -> list[TelemetryEvent]:
    """Convert an existing raw-free app-server pilot report into events.

    The conversion is intentionally lossy: session IDs are hashed, command
    arguments are reduced to a bounded executable name, and only numeric
    measurements survive.  This provides a migration path for the current
    Claude/Codex pilot without making that report format the new event schema.
    """
    sessions = report.get("sessions")
    if not isinstance(sessions, Mapping):
        raise ObservabilityError("pilot report sessions must be an object")
    if baseline_session not in sessions or treatment_session not in sessions:
        raise ObservabilityError("pilot report does not contain both selected sessions")
    timestamp = occurred_at or _utc_now()
    result_events: list[TelemetryEvent] = []
    for session_name, arm in (
        (baseline_session, "baseline"),
        (treatment_session, "treatment"),
    ):
        session = sessions[session_name]
        if not isinstance(session, Mapping):
            raise ObservabilityError(f"pilot session {session_name} must be an object")
        source_session = session.get("session_id", session_name)
        if not isinstance(source_session, str) or not source_session:
            raise ObservabilityError(f"pilot session {session_name} has no session_id")
        digest = sha256_hex(source_session.encode())[:16]
        context = TelemetryContext(
            experiment=experiment_id,
            arm=arm,
            run_id=f"pilot-{digest}",
            session_id=f"pilot-session-{digest}",
            provider=provider,
            model=model,
            harness=harness,
            scenario=scenario,
        )
        sequence = 0

        def add(event: str, current_context: TelemetryContext = context, **fields: Any) -> None:
            nonlocal sequence
            result_events.append(
                TelemetryEvent(current_context, event, sequence, timestamp, fields)
            )
            sequence += 1

        add("run_started")
        usage = session.get("usage")
        if not isinstance(usage, Mapping):
            raise ObservabilityError(f"pilot session {session_name} usage must be an object")
        usage_fields: dict[str, Any] = {}
        for target, names in (
            ("input_tokens", ("input_tokens",)),
            ("output_tokens", ("output_tokens",)),
            ("cached_tokens", ("cached_tokens", "cache_read_tokens")),
            ("cache_write_tokens", ("cache_write_tokens",)),
            ("cost_usd", ("cost_usd", "cost")),
        ):
            value = next((usage.get(name) for name in names if name in usage), None)
            if value is not None:
                usage_fields[target] = value
        if usage_fields:
            add("model_request", **usage_fields)
        commands = session.get("commands", [])
        if not isinstance(commands, list):
            raise ObservabilityError(f"pilot session {session_name} commands must be an array")
        for command in commands:
            if not isinstance(command, Mapping):
                raise ObservabilityError("pilot command metadata must be an object")
            argv = command.get("argv", [])
            executable = Path(argv[0]).name if isinstance(argv, list) and argv else "unknown"
            fields: dict[str, Any] = {
                "tool": executable,
                "success": command.get("command_status") == "success",
            }
            for target, source in (
                ("output_bytes", "raw_bytes"),
                ("visible_bytes", "exposed_bytes"),
            ):
                value = command.get(source)
                if isinstance(value, int) and value >= 0:
                    fields[target] = value
            add("tool_result", **fields)
        conclusion = session.get("conclusion")
        health = conclusion.get("health_conclusion") if isinstance(conclusion, Mapping) else None
        outcome = "pass" if health in {"healthy", "pass", "ok"} else "fail"
        wall_seconds = session.get("wall_seconds")
        completed: dict[str, Any] = {"result": outcome}
        if (
            isinstance(wall_seconds, (int, float))
            and not isinstance(wall_seconds, bool)
            and wall_seconds >= 0
        ):
            completed["duration_ms"] = round(wall_seconds * 1000)
        add("run_completed", **completed)
    return result_events


def read_events(path: Path) -> list[TelemetryEvent]:
    """Read and validate one JSONL event stream without accepting raw bodies."""
    events: list[TelemetryEvent] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ObservabilityError(f"event stream is unreadable: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ObservabilityError(f"invalid event JSON at line {line_number}") from exc
        if not isinstance(value, Mapping):
            raise ObservabilityError(f"event at line {line_number} is not an object")
        try:
            events.append(TelemetryEvent.from_dict(value))
        except ObservabilityError as exc:
            raise ObservabilityError(f"invalid event at line {line_number}: {exc}") from exc
    return events


def _escape_prometheus(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


@dataclass(frozen=True)
class _MetricSample:
    name: str
    value: int | float
    labels: tuple[tuple[str, str], ...]
    help: str
    type: str = "counter"


def _prometheus_line(sample: _MetricSample) -> str:
    label_text = ""
    if sample.labels:
        label_text = "{" + ",".join(
            f'{key}="{_escape_prometheus(value)}"' for key, value in sample.labels
        ) + "}"
    return f"{sample.name}{label_text} {sample.value:g}"


def _stats(values: Sequence[int | float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "sum": 0,
            "mean": None,
            "median": None,
            "stdev": None,
            "variance": None,
            "standard_error": None,
        }
    numeric = [float(value) for value in values]
    deviation = statistics.stdev(numeric) if len(numeric) > 1 else 0.0
    return {
        "count": len(values),
        "sum": sum(values),
        "mean": sum(numeric) / len(numeric),
        "median": statistics.median(numeric),
        "stdev": deviation,
        "variance": deviation**2,
        "standard_error": deviation / math.sqrt(len(numeric)),
    }


@dataclass
class _Run:
    context: TelemetryContext
    events: list[TelemetryEvent] = field(default_factory=list)

    @property
    def result(self) -> str:
        completed = [event for event in self.events if event.event == "run_completed"]
        value = completed[-1].fields.get("result") if completed else None
        return value if value in _RESULTS else "unknown"

    def _sum(self, name: str) -> int | float:
        total: int | float = 0
        for event in self.events:
            value = event.fields.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                total += value
            measurements = event.fields.get("measurements")
            if isinstance(measurements, Mapping):
                alias = next(
                    (key for key, target in _METRIC_ALIASES.items() if target == name), None
                )
                if alias is not None and isinstance(measurements.get(alias), (int, float)):
                    total += measurements[alias]
        return total

    def _last_ms(self, name: str) -> int | float:
        for event in reversed(self.events):
            value = event.fields.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return value
        return 0

    def values(self) -> dict[str, int | float]:
        calls = sum(event.event == "tool_call" for event in self.events)
        results = [event for event in self.events if event.event == "tool_result"]
        if calls == 0:
            calls = len(results)
        failures = sum(event.fields.get("success") is False for event in results)
        return {
            "input_tokens": self._sum("input_tokens"),
            "output_tokens": self._sum("output_tokens"),
            "cached_tokens": self._sum("cached_tokens"),
            "cache_write_tokens": self._sum("cache_write_tokens"),
            "cost_usd": self._sum("cost_usd"),
            "duration_seconds": self._last_ms("duration_ms") / 1000,
            "model_requests": sum(event.event == "model_request" for event in self.events),
            "tool_calls": calls,
            "tool_failures": failures,
            "active_seconds": self._last_ms("active_time_ms") / 1000,
            "lines_changed": self._sum("lines_changed"),
            "evidence_bytes_visible": self._sum("visible_bytes"),
            "outcome": 1 if self.result == "pass" else 0,
            "tool_latency_seconds": sum(
                event.fields.get("duration_ms", 0) / 1000
                for event in results
                if isinstance(event.fields.get("duration_ms", 0), (int, float))
            ),
        }

    def topology(self) -> str:
        nodes: list[str] = []
        for event in sorted(self.events, key=lambda item: item.sequence):
            if event.event == "model_request":
                node = "model"
            elif event.event in {"tool_call", "tool_result"}:
                node = "tool"
            else:
                continue
            if not nodes or nodes[-1] != node:
                nodes.append(node)
        return "→".join(nodes) or "none"


def _runs(events: Iterable[TelemetryEvent]) -> list[_Run]:
    by_id: dict[str, _Run] = {}
    order: list[str] = []
    for event in events:
        run = by_id.get(event.context.run_id)
        if run is None:
            run = _Run(event.context)
            by_id[event.context.run_id] = run
            order.append(event.context.run_id)
        elif run.context != event.context:
            raise ObservabilityError(f"telemetry context changed within run {event.context.run_id}")
        run.events.append(event)
    for run in by_id.values():
        sequences = [event.sequence for event in run.events]
        if len(sequences) != len(set(sequences)):
            raise ObservabilityError(f"duplicate event sequence in run {run.context.run_id}")
        run.events.sort(key=lambda event: event.sequence)
    return [by_id[run_id] for run_id in order]


def _aggregate_samples(events: Iterable[TelemetryEvent]) -> list[_MetricSample]:
    samples: list[_MetricSample] = []
    grouped: dict[tuple[tuple[str, str], ...], list[_Run]] = defaultdict(list)
    for run in _runs(events):
        grouped[tuple(sorted(run.context.labels().items()))].append(run)
    for labels, runs in sorted(grouped.items()):
        def add(
            name: str,
            value: int | float,
            help_text: str,
            sample_labels: tuple[tuple[str, str], ...] = labels,
        ) -> None:
            if value:
                samples.append(_MetricSample(name, value, sample_labels, help_text))

        add("agent_runs_total", len(runs), "Completed or observed agent runs")
        for result in sorted(_RESULTS):
            result_runs = [run for run in runs if run.result == result]
            if result_runs:
                samples.append(
                    _MetricSample(
                        "agent_runs_by_result_total",
                        len(result_runs),
                        tuple(sorted((*labels, (PROMETHEUS_RESULT_LABEL, result)))),
                        "Agent runs grouped by bounded terminal result",
                    )
                )
        totals: dict[str, int | float] = defaultdict(int)
        for run in runs:
            for name, value in run.values().items():
                totals[name] += value
        metric_names = {
            "input_tokens": ("agent_tokens_total", "input", "Agent tokens by kind"),
            "output_tokens": ("agent_tokens_total", "output", "Agent tokens by kind"),
            "cached_tokens": ("agent_tokens_total", "cached", "Agent tokens by kind"),
            "cache_write_tokens": ("agent_tokens_total", "cache_write", "Agent tokens by kind"),
            "cost_usd": ("agent_cost_usd_total", None, "Agent cost in USD"),
            "duration_seconds": ("agent_run_duration_seconds_total", None, "Agent run duration"),
            "model_requests": ("agent_model_requests_total", None, "Model requests"),
            "tool_calls": ("agent_tool_calls_total", None, "Tool calls"),
            "tool_failures": ("agent_tool_failures_total", None, "Tool failures"),
            "active_seconds": ("agent_active_seconds_total", None, "Agent active time"),
            "lines_changed": ("agent_lines_changed_total", None, "Lines changed"),
            "evidence_bytes_visible": (
                "agent_evidence_bytes_visible_total",
                None,
                "Model-visible evidence bytes",
            ),
            "tool_latency_seconds": (
                "agent_tool_latency_seconds_total",
                None,
                "Tool latency in seconds",
            ),
        }
        for key, (name, dimension, help_text) in metric_names.items():
            value = totals[key]
            if value:
                sample_labels = (
                    labels
                    if dimension is None
                    else tuple(sorted((*labels, ("token_type", dimension))))
                )
                samples.append(_MetricSample(name, value, sample_labels, help_text))
    return samples


def render_prometheus(events: Iterable[TelemetryEvent]) -> str:
    """Render bounded aggregate counters in Prometheus text format."""
    samples = _aggregate_samples(events)
    lines: list[str] = []
    emitted_help: set[str] = set()
    emitted_type: set[str] = set()
    for sample in samples:
        if sample.name not in emitted_help:
            lines.append(f"# HELP {sample.name} {sample.help}")
            emitted_help.add(sample.name)
        if sample.name not in emitted_type:
            lines.append(f"# TYPE {sample.name} {sample.type}")
            emitted_type.add(sample.name)
        lines.append(_prometheus_line(sample))
    return "\n".join(lines) + ("\n" if lines else "")


def _timestamp_ns(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObservabilityError(f"invalid event timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return str(int(parsed.timestamp() * 1_000_000_000))


def build_loki_push(events: Iterable[TelemetryEvent]) -> dict[str, Any]:
    """Build a Loki push payload with IDs in log JSON, never stream labels."""
    streams: dict[tuple[tuple[str, str], ...], list[list[str]]] = defaultdict(list)
    for event in events:
        labels = tuple(sorted(event.context.labels().items()))
        streams[labels].append(
            [_timestamp_ns(event.occurred_at), canonical_json_text(event.to_dict())]
        )
    return {
        "streams": [
            {"stream": dict(labels), "values": values}
            for labels, values in sorted(streams.items())
        ]
    }


def _otlp_attributes(attributes: Mapping[str, object]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key, value in sorted(attributes.items()):
        if isinstance(value, bool):
            typed: dict[str, Any] = {"boolValue": value}
        elif isinstance(value, int):
            typed = {"intValue": str(value)}
        elif isinstance(value, float):
            typed = {"doubleValue": value}
        else:
            typed = {"stringValue": str(value)}
        result.append({"key": key, "value": typed})
    return result


def build_otlp_logs(events: Iterable[TelemetryEvent]) -> dict[str, Any]:
    """Build OTLP/HTTP JSON logs for an OpenTelemetry Collector."""
    records = []
    for event in events:
        attributes = {
            "event.name": event.event,
            "experiment": event.context.experiment,
            "arm": event.context.arm,
            "run.id": event.context.run_id,
            "session.id": event.context.session_id,
        }
        records.append(
            {
                "timeUnixNano": _timestamp_ns(event.occurred_at),
                "body": {"stringValue": canonical_json_text(event.to_dict())},
                "attributes": _otlp_attributes(attributes),
            }
        )
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": _otlp_attributes({"service.name": "outctl"})},
                "scopeLogs": [{"scope": {"name": "outctl.observability"}, "logRecords": records}],
            }
        ]
    }


def build_otlp_metrics(events: Iterable[TelemetryEvent]) -> dict[str, Any]:
    """Build OTLP/HTTP JSON metrics using the same bounded samples as Prometheus."""
    now = _timestamp_ns(_utc_now())
    metrics: list[dict[str, Any]] = []
    for sample in _aggregate_samples(events):
        data_point: dict[str, Any] = {
            "attributes": _otlp_attributes(dict(sample.labels)),
            "timeUnixNano": now,
        }
        if isinstance(sample.value, int):
            data_point["asInt"] = str(sample.value)
        else:
            data_point["asDouble"] = sample.value
        metrics.append(
            {
                "name": sample.name,
                "description": sample.help,
                "unit": "1",
                "sum": {
                    "dataPoints": [data_point],
                    "aggregationTemporality": 2,
                    "isMonotonic": True,
                },
            }
        )
    return {
        "resourceMetrics": [
            {
                "resource": {"attributes": _otlp_attributes({"service.name": "outctl"})},
                "scopeMetrics": [{"scope": {"name": "outctl.observability"}, "metrics": metrics}],
            }
        ]
    }


def _post_json(endpoint: str, payload: Mapping[str, Any], *, timeout: float) -> None:
    request = urllib.request.Request(
        endpoint,
        data=canonical_json_text(dict(payload)).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise ObservabilityError(f"telemetry endpoint returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise ObservabilityError(f"telemetry endpoint is unavailable: {exc}") from exc


def export_loki(events: Iterable[TelemetryEvent], endpoint: str, *, timeout: float = 10.0) -> None:
    """Push structured events to an appservice-provided Loki endpoint."""
    _post_json(endpoint.rstrip("/") + "/loki/api/v1/push", build_loki_push(events), timeout=timeout)


def export_otlp(
    events: Iterable[TelemetryEvent], endpoint: str, *, timeout: float = 10.0
) -> None:
    """Push logs and metrics to an OTLP/HTTP Collector endpoint."""
    materialized = list(events)
    base = endpoint.rstrip("/")
    _post_json(base + "/v1/logs", build_otlp_logs(materialized), timeout=timeout)
    _post_json(base + "/v1/metrics", build_otlp_metrics(materialized), timeout=timeout)


@dataclass(frozen=True)
class ExperimentDefinition:
    """Small HLA-facing experiment definition."""

    experiment_id: str
    baseline: str
    treatment: str
    metrics: tuple[str, ...]
    derived: tuple[str, ...] = ()
    outcome: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ExperimentDefinition:
        nested = value.get("experiment")
        if isinstance(nested, Mapping):
            root: Mapping[str, Any] = dict(nested)
            merged = dict(root)
            for name in ("metrics", "derived", "outcome"):
                if name in value and name not in merged:
                    merged[name] = value[name]
            root = merged
        else:
            root = value
        experiment_id = root.get("id")
        baseline = root.get("baseline")
        treatment = root.get("treatment")
        metrics = root.get("metrics", [])
        derived = root.get("derived", [])
        if not all(
            isinstance(item, str) and item for item in (experiment_id, baseline, treatment)
        ):
            raise ObservabilityError("experiment id, baseline, and treatment are required")
        assert isinstance(experiment_id, str)
        assert isinstance(baseline, str)
        assert isinstance(treatment, str)
        if not isinstance(metrics, list) or not metrics:
            raise ObservabilityError("experiment metrics must be a non-empty list")
        if not all(isinstance(item, str) and item in _METRIC_ALIASES for item in metrics):
            raise ObservabilityError("experiment contains an unsupported metric")
        if not isinstance(derived, list) or not all(item in _DERIVED for item in derived):
            raise ObservabilityError("experiment contains an unsupported derived metric")
        outcome = root.get("outcome", {})
        if not isinstance(outcome, Mapping):
            raise ObservabilityError("experiment outcome must be an object")
        return cls(
            experiment_id=experiment_id,
            baseline=baseline,
            treatment=treatment,
            metrics=tuple(dict.fromkeys(metrics)),
            derived=tuple(dict.fromkeys(derived)),
            outcome=dict(outcome),
        )


def _relative_delta(baseline: float | int | None, treatment: float | int | None) -> float | None:
    if baseline is None or baseline == 0 or treatment is None:
        return None
    return (float(treatment) - float(baseline)) / float(baseline) * 100


def _absolute_delta(baseline: float | int | None, treatment: float | int | None) -> float | None:
    if baseline is None or treatment is None:
        return None
    return float(treatment) - float(baseline)


def _arm_stats(runs: Sequence[_Run], metric: str) -> dict[str, Any]:
    internal = _METRIC_ALIASES[metric]
    values = [run.values()[internal] for run in runs]
    return _stats(values)


def _derived_stats(runs: Sequence[_Run], name: str) -> dict[str, Any]:
    if name == "model_decision_boundaries":
        return _stats([run.values()["model_requests"] for run in runs])
    if name == "tools_per_model_round":
        return _stats(
            [
                run.values()["tool_calls"] / run.values()["model_requests"]
                for run in runs
                if run.values()["model_requests"]
            ]
        )
    if name == "evidence_bytes_visible":
        return _stats([run.values()["evidence_bytes_visible"] for run in runs])
    if name == "tokens_per_success":
        return _stats(
            [
                run.values()["input_tokens"] + run.values()["output_tokens"]
                for run in runs
                if run.result == "pass"
            ]
        )
    if name == "cost_per_success":
        return _stats([run.values()["cost_usd"] for run in runs if run.result == "pass"])
    if name == "interaction_topology":
        return dict(sorted(Counter(run.topology() for run in runs).items()))
    raise ObservabilityError(f"unsupported derived metric: {name}")


def _outcome(runs: Sequence[_Run]) -> dict[str, Any]:
    counts = Counter(run.result for run in runs)
    total = len(runs)
    return {
        "runs": total,
        "counts": {result: counts.get(result, 0) for result in sorted(_RESULTS)},
        "pass_rate": counts.get("pass", 0) / total if total else None,
    }


def compare_experiment(
    definition: ExperimentDefinition | Mapping[str, Any],
    events: Iterable[TelemetryEvent],
) -> dict[str, Any]:
    """Produce a raw-free baseline/treatment report from structured events."""
    experiment = (
        definition
        if isinstance(definition, ExperimentDefinition)
        else ExperimentDefinition.from_mapping(definition)
    )
    selected = [event for event in events if event.context.experiment == experiment.experiment_id]
    runs = _runs(selected)
    arms = {
        experiment.baseline: [run for run in runs if run.context.arm == experiment.baseline],
        experiment.treatment: [run for run in runs if run.context.arm == experiment.treatment],
    }
    unknown_arms = sorted(
        {run.context.arm for run in runs} - {experiment.baseline, experiment.treatment}
    )
    if unknown_arms:
        raise ObservabilityError(f"events contain arms outside the experiment: {unknown_arms}")
    metric_report: dict[str, Any] = {}
    for metric in experiment.metrics:
        baseline_stats = _arm_stats(arms[experiment.baseline], metric)
        treatment_stats = _arm_stats(arms[experiment.treatment], metric)
        metric_report[metric] = {
            "baseline": baseline_stats,
            "treatment": treatment_stats,
            "delta": {
                "absolute_mean": (
                    treatment_stats["mean"] - baseline_stats["mean"]
                    if treatment_stats["mean"] is not None and baseline_stats["mean"] is not None
                    else None
                ),
                "relative_pct": _relative_delta(baseline_stats["mean"], treatment_stats["mean"]),
            },
        }
    derived_report: dict[str, Any] = {}
    for name in experiment.derived:
        derived_report[name] = {
            "baseline": _derived_stats(arms[experiment.baseline], name),
            "treatment": _derived_stats(arms[experiment.treatment], name),
        }
    generated_at = max((event.occurred_at for event in selected), default=None)
    baseline_outcome = _outcome(arms[experiment.baseline])
    treatment_outcome = _outcome(arms[experiment.treatment])
    return {
        "schema_version": REPORT_SCHEMA,
        "experiment_id": experiment.experiment_id,
        "baseline": experiment.baseline,
        "treatment": experiment.treatment,
        "source": {"events": len(selected), "runs": len(runs)},
        "metrics": metric_report,
        "derived": derived_report,
        "outcome": {
            "baseline": baseline_outcome,
            "treatment": treatment_outcome,
            "pass_rate_delta": _absolute_delta(
                baseline_outcome["pass_rate"], treatment_outcome["pass_rate"]
            ),
            "pass_rate_delta_relative_pct": _relative_delta(
                baseline_outcome["pass_rate"], treatment_outcome["pass_rate"]
            ),
            "query": experiment.outcome.get("query"),
        },
        "generated_at": generated_at,
        "report_digest": sha256_hex(
            canonical_json_text(
                {
                    "experiment_id": experiment.experiment_id,
                    "metrics": metric_report,
                    "derived": derived_report,
                    "outcome": {"baseline": baseline_outcome, "treatment": treatment_outcome},
                }
            ).encode()
        ),
    }


def load_document(path: Path) -> Mapping[str, Any]:
    """Load a JSON or YAML experiment document."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ObservabilityError(f"document is unreadable: {exc}") from exc
    try:
        if path.suffix.casefold() in {".yaml", ".yml"}:
            import yaml  # type: ignore[import-untyped]

            value = yaml.safe_load(text)
        else:
            value = json.loads(text)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ObservabilityError(f"document is malformed: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ObservabilityError("document root must be an object")
    return value
