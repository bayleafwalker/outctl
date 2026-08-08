"""Local, metadata-only support for the concurrent Terra pilot.

The pilot is deliberately separate from the capture engine.  It can validate
fixture evidence offline, but refuses a live run unless the installed ``outctl``
already provides the required enforce and retrieval commands.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Barrier as ThreadBarrier
from threading import Thread
from typing import Any, cast

MODEL = "gpt-5.6-terra"
SESSIONS = frozenset(("A", "B"))
REQUIRED_USAGE = frozenset(
    ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")
)
APP_SERVER_TOKEN_FIELDS = frozenset(
    (
        "inputTokens",
        "cachedInputTokens",
        "cacheWriteInputTokens",
        "outputTokens",
        "reasoningOutputTokens",
        "totalTokens",
    )
)
MUTATING_KUBECTL = frozenset(
    ("apply", "create", "delete", "patch", "replace", "edit", "scale", "rollout")
)
RAW_CONTENT_KEYS = frozenset(
    ("stdout", "stderr", "projection", "raw_output", "output_text", "content")
)


class PilotError(ValueError):
    """Raised when pilot evidence is unsafe, incomplete, or incomparable."""


class PilotReportError(ValueError):
    """Raised when a qualitative report is incomplete or contains bodies."""


@dataclass(frozen=True)
class PilotReportSummary:
    harness: str
    command_class: str
    policy_digest: str
    baseline_exposed_tokens: int
    enforce_exposed_tokens: int
    retrieval_count: int


@dataclass(frozen=True)
class AppServerTokenUsage:
    """Cumulative, per-thread token counters from the app-server protocol."""

    input_tokens: int
    cached_input_tokens: int
    cache_write_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int
    total_tokens: int

    @property
    def model_context_memory(self) -> int:
        """Cached input is a subset of input, so do not double-count it."""
        return self.input_tokens

    @property
    def aggregate_cache_tokens(self) -> int:
        return self.cached_input_tokens + self.cache_write_input_tokens

    def report_fields(self) -> dict[str, int | None | str]:
        return {
            "input_tokens": self.input_tokens,
            "cache_read_tokens": self.cached_input_tokens,
            "cache_write_tokens": self.cache_write_input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_output_tokens": self.reasoning_output_tokens,
            "total_tokens": self.total_tokens,
            "model_context_memory": self.model_context_memory,
            "aggregate_cache_tokens": self.aggregate_cache_tokens,
            "reported_cost": None,
            "cost_telemetry_status": "provider_unavailable",
        }


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost: float

    @property
    def model_context_memory(self) -> int:
        return self.input_tokens + self.cache_read_tokens

    @property
    def aggregate_cache_tokens(self) -> int:
        return self.cache_read_tokens + self.cache_write_tokens


@dataclass(frozen=True)
class SessionTelemetry:
    session: str
    session_id: str
    usage: Usage
    wall_seconds: float


def _number(value: object, name: str, *, integral: bool = False) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise PilotError(f"invalid {name}")
    if integral and int(value) != value:
        raise PilotError(f"invalid {name}")
    return int(value) if integral else float(value)


def parse_app_server_token_usage(event: object, expected_thread_id: str) -> AppServerTokenUsage:
    """Accept only the terminal, metadata-only token usage notification."""
    if not isinstance(event, dict) or event.get("method") != "thread/tokenUsage/updated":
        raise PilotError("expected thread/tokenUsage/updated notification")
    params = event.get("params")
    if not isinstance(params, dict) or params.get("threadId") != expected_thread_id:
        raise PilotError("token telemetry belongs to a different thread")
    token_usage = params.get("tokenUsage")
    if not isinstance(token_usage, dict):
        raise PilotError("token telemetry is missing tokenUsage")
    total = token_usage.get("total")
    if not isinstance(total, dict) or not total.keys() >= APP_SERVER_TOKEN_FIELDS:
        raise PilotError("telemetry-incomplete: app-server token fields are missing")
    values = {
        field: int(_number(total[field], field, integral=True)) for field in APP_SERVER_TOKEN_FIELDS
    }
    if values["cachedInputTokens"] > values["inputTokens"]:
        raise PilotError("cached input tokens exceed input tokens")
    return AppServerTokenUsage(
        input_tokens=values["inputTokens"],
        cached_input_tokens=values["cachedInputTokens"],
        cache_write_input_tokens=values["cacheWriteInputTokens"],
        output_tokens=values["outputTokens"],
        reasoning_output_tokens=values["reasoningOutputTokens"],
        total_tokens=values["totalTokens"],
    )


def validate_app_server_schema(schema_path: Path) -> None:
    """Fail closed unless the pinned schema advertises complete token telemetry."""
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PilotError("unable to read app-server schema") from exc
    if not isinstance(schema, dict):
        raise PilotError("invalid app-server schema")
    definitions = schema.get("definitions")
    if not isinstance(definitions, dict):
        raise PilotError("app-server schema has no definitions")
    notification = definitions.get("ThreadTokenUsageUpdatedNotification")
    breakdown = definitions.get("TokenUsageBreakdown")
    if not isinstance(notification, dict) or not isinstance(breakdown, dict):
        raise PilotError("app-server schema lacks token usage notification")
    properties = breakdown.get("properties")
    if not isinstance(properties, dict) or not properties.keys() >= APP_SERVER_TOKEN_FIELDS:
        raise PilotError("app-server schema lacks required token fields")


def run_app_server_turn(
    *,
    codex_home: Path,
    cwd: Path,
    prompt: str,
    model: str,
    spool_root: Path,
) -> tuple[str, AppServerTokenUsage]:
    """Run one ephemeral, read-only turn and retain only its token notification.

    JSON-RPC item, message, and command-output notifications are intentionally
    discarded in memory.  A caller must validate the generated schema before
    selecting this experimental transport.
    """
    environment = {
        **os.environ,
        "CODEX_HOME": str(codex_home),
        "OUTCTL_PILOT_SPOOL": str(spool_root),
        "NO_COLOR": "1",
    }
    process = subprocess.Popen(
        ["codex", "app-server", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=environment,
    )
    if process.stdin is None or process.stdout is None:  # pragma: no cover
        raise PilotError("app-server stdio was unavailable")
    stdin = process.stdin
    stdout = process.stdout
    request_id = 0

    def request(method: str, params: dict[str, object]) -> dict[str, Any]:
        nonlocal request_id
        request_id += 1
        stdin.write(json.dumps({"id": request_id, "method": method, "params": params}) + "\n")
        stdin.flush()
        while line := stdout.readline():
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PilotError("app-server emitted malformed JSON") from exc
            if not isinstance(message, dict):
                raise PilotError("app-server emitted a non-object message")
            if message.get("id") == request_id:
                result = message.get("result")
                if not isinstance(result, dict):
                    raise PilotError(f"app-server {method} did not return an object")
                return result
        raise PilotError(f"app-server closed during {method}")

    try:
        request("initialize", {"clientInfo": {"name": "outctl-pilot", "version": "1"}})
        started = request(
            "thread/start",
            {
                "cwd": str(cwd),
                "model": model,
                "sandbox": "read-only",
                "ephemeral": True,
                "approvalPolicy": "never",
            },
        )
        thread = started.get("thread")
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            raise PilotError("app-server did not return a thread id")
        thread_id = thread["id"]
        turn = request(
            "turn/start",
            {"threadId": thread_id, "input": [{"type": "text", "text": prompt}]},
        )
        turn_value = turn.get("turn")
        if not isinstance(turn_value, dict) or not isinstance(turn_value.get("id"), str):
            raise PilotError("app-server did not return a turn id")
        latest: AppServerTokenUsage | None = None
        while line := stdout.readline():
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                raise PilotError("app-server emitted malformed JSON") from exc
            if not isinstance(message, dict):
                raise PilotError("app-server emitted a non-object message")
            if message.get("method") == "thread/tokenUsage/updated":
                latest = parse_app_server_token_usage(message, thread_id)
            if message.get("method") == "turn/completed":
                params = message.get("params")
                if isinstance(params, dict) and params.get("threadId") == thread_id:
                    if latest is None:
                        raise PilotError("telemetry-incomplete: no app-server token usage update")
                    return thread_id, latest
        raise PilotError("app-server closed before turn completion")
    finally:
        process.terminate()
        process.wait(timeout=10)


def _first(mapping: dict[str, Any], keys: Iterable[str]) -> object | None:
    for key in keys:
        if key in mapping:
            return cast(object, mapping[key])
    return None


def _usage_from_event(event: dict[str, Any]) -> Usage | None:
    """Extract only complete counters from known Codex JSON event shapes."""
    candidates: list[dict[str, Any]] = []
    for value in (event.get("usage"), event.get("token_usage")):
        if isinstance(value, dict):
            candidates.append(value)
    response = event.get("response")
    if isinstance(response, dict) and isinstance(response.get("usage"), dict):
        candidates.append(response["usage"])
    for usage in candidates:
        input_value = _first(usage, ("input_tokens", "input"))
        output_value = _first(usage, ("output_tokens", "output"))
        read_value = _first(usage, ("cache_read_tokens", "cached_input_tokens", "cache_read"))
        write_value = _first(
            usage, ("cache_write_tokens", "cache_creation_input_tokens", "cache_write")
        )
        cost_value = _first(usage, ("cost", "cost_usd", "reported_cost"))
        values = (input_value, output_value, read_value, write_value, cost_value)
        if all(value is not None for value in values):
            return Usage(
                input_tokens=_number(input_value, "input_tokens", integral=True),  # type: ignore[arg-type]
                output_tokens=_number(output_value, "output_tokens", integral=True),  # type: ignore[arg-type]
                cache_read_tokens=_number(read_value, "cache_read_tokens", integral=True),  # type: ignore[arg-type]
                cache_write_tokens=_number(write_value, "cache_write_tokens", integral=True),  # type: ignore[arg-type]
                cost=_number(cost_value, "reported cost"),
            )
    return None


def parse_codex_jsonl(path: Path, session: str) -> SessionTelemetry:
    """Parse one session stream without accepting telemetry from another session."""
    if session not in SESSIONS:
        raise PilotError("unknown session")
    session_ids: set[str] = set()
    usage: Usage | None = None
    started: float | None = None
    ended: float | None = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PilotError(f"malformed JSONL at line {number}") from exc
        if not isinstance(event, dict):
            raise PilotError(f"non-object event at line {number}")
        event_session = _first(event, ("session_id", "thread_id"))
        if event_session is not None:
            if not isinstance(event_session, str) or not event_session:
                raise PilotError(f"invalid session id at line {number}")
            session_ids.add(event_session)
        timestamp = _first(event, ("timestamp", "created_at"))
        if isinstance(timestamp, int | float) and not isinstance(timestamp, bool):
            started = float(timestamp) if started is None else min(started, float(timestamp))
            ended = float(timestamp) if ended is None else max(ended, float(timestamp))
        found = _usage_from_event(event)
        if found is not None:
            if usage is not None and usage != found:
                raise PilotError("conflicting usage events")
            usage = found
    if len(session_ids) != 1:
        raise PilotError("stream must contain exactly one session id")
    if usage is None:
        raise PilotError("telemetry-incomplete: missing input/output/cache/cost values")
    return SessionTelemetry(
        session=session,
        session_id=session_ids.pop(),
        usage=usage,
        wall_seconds=0.0 if started is None or ended is None else max(0.0, ended - started),
    )


def _reject_raw_content(value: object, trail: str = "report") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in RAW_CONTENT_KEYS:
                raise PilotError(f"raw or projection content is forbidden at {trail}.{key}")
            _reject_raw_content(nested, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_raw_content(nested, f"{trail}[{index}]")


def validate_report(report: dict[str, Any]) -> None:
    """Validate the report's safety, telemetry, and retrieval proof invariants."""
    _reject_raw_content(report)
    sessions = report.get("sessions")
    if not isinstance(sessions, dict) or set(sessions) != SESSIONS:
        raise PilotError("report must contain exactly A and B")
    seen_ids: set[str] = set()
    for name, item in sessions.items():
        if not isinstance(item, dict):
            raise PilotError(f"invalid session report {name}")
        session_id = item.get("session_id")
        if not isinstance(session_id, str) or not session_id or session_id in seen_ids:
            raise PilotError("mixed or duplicate session ids")
        seen_ids.add(session_id)
        usage = item.get("usage")
        if not isinstance(usage, dict) or not usage.keys() >= REQUIRED_USAGE:
            raise PilotError(f"telemetry-incomplete for {name}")
        for key in REQUIRED_USAGE:
            _number(usage[key], key, integral=key != "cost")
        commands = item.get("commands")
        if not isinstance(commands, list):
            raise PilotError(f"missing command metadata for {name}")
        for command in commands:
            if not isinstance(command, dict):
                raise PilotError("invalid command metadata")
            argv = command.get("argv")
            if not isinstance(argv, list) or not all(isinstance(token, str) for token in argv):
                raise PilotError("command metadata requires argv")
            if any(token in MUTATING_KUBECTL for token in argv):
                raise PilotError("mutation command class is forbidden")
    retrieval = sessions["A"].get("retrieval")
    if not isinstance(retrieval, dict) or retrieval.get("count") != 1:
        raise PilotError("guided session needs exactly one retrieval")
    if (
        retrieval.get("from_existing_capture") is not True
        or retrieval.get("reran_kubectl") is not False
    ):
        raise PilotError("guided retrieval proof is invalid")
    if sessions["B"].get("retrieval", {}).get("count", 0) != 0:
        raise PilotError("control must not claim an outctl retrieval")


def review_verdict(report: dict[str, Any]) -> str:
    """Compute the conservative review verdict; content equivalence is human-reviewed."""
    validate_report(report)
    review = report.get("review")
    if not isinstance(review, dict) or review.get("health_conclusion_preserved") is not True:
        return "adjust"
    # Token/cost deltas are recorded as decision evidence. The pilot assesses
    # direction and harness behavior; it does not impose a numeric release bar.
    return "continue"


def _report_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PilotReportError(f"{name} must be an object")
    return value


def _report_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PilotReportError(f"{name} must be a non-empty string")
    return value


def _report_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PilotReportError(f"{name} must be a non-negative integer")
    return value


def _reject_qualitative_bodies(value: object) -> None:
    banned = ("raw_output", "stdout", "stderr", "projection_text", "inline_text")
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise PilotReportError("report keys must be strings")
            if any(part in key.casefold() for part in banned):
                raise PilotReportError(f"raw/model body field is forbidden: {key}")
            _reject_qualitative_bodies(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_qualitative_bodies(nested)


def validate_pilot_report(report: Mapping[str, Any]) -> PilotReportSummary:
    """Keep compatibility with the existing qualitative pilot report contract."""
    _reject_qualitative_bodies(report)
    pilot = _report_mapping(report.get("pilot"), "pilot")
    harness = _report_string(pilot.get("harness"), "pilot.harness").casefold()
    if harness not in {"codex", "claude"}:
        raise PilotReportError("pilot.harness must be codex or claude")
    command_class = _report_string(pilot.get("command_class"), "pilot.command_class")
    if command_class != "appservice-health-check":
        raise PilotReportError("pilot.command_class must be appservice-health-check")
    policy_digest = _report_string(pilot.get("policy_digest"), "pilot.policy_digest")
    baseline = _report_mapping(report.get("baseline"), "baseline")
    enforce = _report_mapping(report.get("enforce"), "enforce")
    baseline_tokens = _report_int(baseline.get("exposed_tokens"), "baseline.exposed_tokens")
    enforce_tokens = _report_int(enforce.get("exposed_tokens"), "enforce.exposed_tokens")
    for field in (
        "raw_tokens",
        "retrieved_tokens",
        "retrieval_count",
        "wall_time_ms",
        "wrapper_overhead_ms",
    ):
        _report_int(enforce.get(field), f"enforce.{field}")
    assessment = _report_mapping(report.get("assessment"), "assessment")
    for field in ("harness_native_context_management", "outctl_increment", "recommendation"):
        _report_string(assessment.get(field), f"assessment.{field}")
    return PilotReportSummary(
        harness=harness,
        command_class=command_class,
        policy_digest=policy_digest,
        baseline_exposed_tokens=baseline_tokens,
        enforce_exposed_tokens=enforce_tokens,
        retrieval_count=_report_int(enforce.get("retrieval_count"), "enforce.retrieval_count"),
    )


def _repo_commit(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise PilotError(f"not a pinned Git checkout: {path}")
    return result.stdout.strip()


def _mode(path: Path, mode: int) -> None:
    path.chmod(mode)


def _copy_auth(source_home: Path, target_home: Path) -> None:
    auth = source_home / "auth.json"
    if not auth.is_file():
        raise PilotError("Codex auth.json is absent; refusing an unauthenticated isolated profile")
    shutil.copy2(auth, target_home / "auth.json")
    _mode(target_home / "auth.json", stat.S_IRUSR | stat.S_IWUSR)


def _preflight(kubeconfig: Path, context: str, namespace: str) -> None:
    if not kubeconfig.is_file():
        raise PilotError("explicit kubeconfig does not exist")
    current = subprocess.run(
        ["kubectl", "--kubeconfig", str(kubeconfig), "config", "current-context"],
        capture_output=True,
        text=True,
        check=False,
    )
    if current.returncode or current.stdout.strip() != context:
        raise PilotError("explicit kubeconfig/context preflight failed")
    for verb in ("get", "list"):
        for resource in ("deployments", "pods", "events"):
            allowed = subprocess.run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(kubeconfig),
                    "auth",
                    "can-i",
                    verb,
                    resource,
                    "--namespace",
                    namespace,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if allowed.returncode or allowed.stdout.strip().lower() != "yes":
                raise PilotError(f"read-only RBAC preflight failed for {verb} {resource}")
    for verb in ("create", "patch", "delete", "deletecollection"):
        for resource in ("deployments", "pods", "events"):
            allowed = subprocess.run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(kubeconfig),
                    "auth",
                    "can-i",
                    verb,
                    resource,
                    "--namespace",
                    namespace,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            # ``kubectl auth can-i`` returns status 1 for the expected answer
            # ``no``. Its stdout is the authoritative result; an invocation
            # error has no affirmative ``no`` output and still fails closed.
            if allowed.stdout.strip().lower() != "no":
                raise PilotError(f"mutation RBAC must be denied for {verb} {resource}")


def _outctl_capability() -> None:
    help_result = subprocess.run(["outctl", "--help"], capture_output=True, text=True, check=False)
    text = help_result.stdout + help_result.stderr
    if help_result.returncode or not all(word in text for word in ("run", "inspect")):
        raise PilotError(
            "live pilot requires an installed outctl with run and inspect retrieval support"
        )


def _metadata_event(line: str) -> str:
    """Keep only usage/session metadata; never retain model/tool content."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        raise PilotError("Codex emitted malformed JSONL") from exc
    if not isinstance(event, dict):
        raise PilotError("Codex emitted a non-object JSONL event")
    metadata: dict[str, object] = {}
    for key in ("type", "session_id", "thread_id", "timestamp", "created_at"):
        value = event.get(key)
        if isinstance(value, str | int | float) and not isinstance(value, bool):
            metadata[key] = value
    usage = _usage_from_event(event)
    if usage is not None:
        metadata["usage"] = asdict(usage)
    return json.dumps(metadata, sort_keys=True) + "\n"


def _copy_metadata(source: Iterable[str], destination: Path) -> None:
    with destination.open("w", encoding="utf-8") as output:
        _mode(destination, stat.S_IRUSR | stat.S_IWUSR)
        for line in source:
            output.write(_metadata_event(line))


def _read_event_log(path: Path) -> list[dict[str, object]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    except (OSError, json.JSONDecodeError) as exc:
        raise PilotError("pilot evidence event log is unavailable or malformed") from exc


def _guided_evidence(spool: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    commands = _read_event_log(spool / "command-events.jsonl")
    retrievals = _read_event_log(spool / "retrieval-events.jsonl")
    if len(commands) != 4 or any(event.get("executable") != "kubectl" for event in commands):
        raise PilotError("guided evidence requires the four captured kubectl corpus commands")
    capture_ids = [event.get("capture_id") for event in commands]
    if not all(isinstance(capture_id, str) for capture_id in capture_ids):
        raise PilotError("guided command evidence lacks capture ids")
    if len(retrievals) != 1 or retrievals[0].get("capture_id") not in capture_ids:
        raise PilotError("guided evidence requires exactly one retrieval of a corpus capture")
    capture_id = retrievals[0]["capture_id"]
    assert isinstance(capture_id, str)
    manifest = spool / "captures" / capture_id / "manifest.json"
    try:
        capture = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PilotError("guided capture manifest is unavailable") from exc
    if not isinstance(capture, dict):
        raise PilotError("guided capture manifest is invalid")
    streams = capture.get("streams")
    stdout = streams.get("stdout") if isinstance(streams, dict) else None
    stderr = streams.get("stderr") if isinstance(streams, dict) else None
    raw_bytes = sum(entry.get("bytes", 0) for entry in (stdout, stderr) if isinstance(entry, dict))
    return (
        [
            {
                "argv": ["kubectl"],
                "command_status": capture.get("command", {}).get("exit_code")
                if isinstance(capture.get("command"), dict)
                else None,
                "capture_status": capture.get("capture_status"),
                "raw_bytes": raw_bytes,
            }
            for command in commands
            for capture_id in [command["capture_id"]]
            if isinstance(capture_id, str)
            for capture in [
                json.loads(
                    (spool / "captures" / capture_id / "manifest.json").read_text(encoding="utf-8")
                )
            ]
            if isinstance(capture, dict)
        ],
        {"count": 1, "from_existing_capture": True, "reran_kubectl": False},
    )


def launch(args: argparse.Namespace) -> Path:
    root = Path(__file__).parents[2]
    appservice = Path(args.appservice).resolve()
    kubeconfig = Path(args.kubeconfig).resolve()
    run_root = Path(args.output).resolve() / f"terra-ab-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    _preflight(kubeconfig, args.context, args.namespace)
    _outctl_capability()
    run_root.mkdir(parents=True, mode=0o700)
    _mode(run_root, 0o700)
    metadata = {
        "model": MODEL,
        "outctl_commit": _repo_commit(root),
        "appservice_commit": _repo_commit(appservice),
    }
    (run_root / "pins.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
    )
    source_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    prompt = (root / "pilot" / "prompt.md").read_text(encoding="utf-8")
    corpus = (
        (root / "pilot" / "corpus.json")
        .read_text(encoding="utf-8")
        .replace("{KUBECONFIG}", str(kubeconfig))
    )
    sessions: dict[str, tuple[Path, Path, Path]] = {}
    for name in sorted(SESSIONS):
        session_root = run_root / name
        home = session_root / "codex-home"
        work = session_root / "work"
        spool = work / "spool"
        for directory in (home, spool, work):
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            _mode(directory, 0o700)
        _copy_auth(source_home, home)
        (work / "CORPUS.json").write_text(corpus, encoding="utf-8")
        (work / "PROMPT.md").write_text(prompt, encoding="utf-8")
        if name == "A":
            shutil.copy2(root / "pilot" / "guided" / "AGENTS.md", work / "AGENTS.md")
            skill_target = home / "skills" / "outctl-health-check"
            skill_target.mkdir(parents=True)
            shutil.copy2(
                root / "pilot" / "guided" / "skills" / "outctl-health-check" / "SKILL.md",
                skill_target / "SKILL.md",
            )
            rules = home / "rules"
            rules.mkdir()
            shutil.copy2(
                root / "pilot" / "guided" / "rules" / "kubectl.rules", rules / "default.rules"
            )
            (home / "guided.config.toml").write_text(
                'model = "gpt-5.6-terra"\n[features]\nskills = true\n', encoding="utf-8"
            )
        else:
            (home / "control.config.toml").write_text('model = "gpt-5.6-terra"\n', encoding="utf-8")
        sessions[name] = (home, work, spool)
    start = ThreadBarrier(len(SESSIONS))
    telemetry: dict[str, tuple[str, AppServerTokenUsage]] = {}
    failures: list[BaseException] = []

    def run_session(name: str) -> None:
        home, work, spool = sessions[name]
        try:
            start.wait()
            telemetry[name] = run_app_server_turn(
                codex_home=home, cwd=work, prompt=prompt, model=MODEL, spool_root=spool
            )
        except BaseException as exc:  # surfaced after both workers finish
            failures.append(exc)

    workers = [Thread(target=run_session, args=(name,), daemon=True) for name in sorted(SESSIONS)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    if failures:
        raise PilotError(f"app-server pilot session failed: {failures[0]}")
    guided_commands, guided_retrieval = _guided_evidence(sessions["A"][2])
    report = {
        "schema_version": 1,
        "pins": metadata,
        "sessions": {
            name: {
                "session_id": data[0],
                "usage": data[1].report_fields(),
                "wall_seconds": 0.0,
                "commands": [] if name == "B" else guided_commands,
                "retrieval": {"count": 0} if name == "B" else guided_retrieval,
            }
            for name, data in telemetry.items()
        },
        "review": {"health_conclusion_preserved": False},
    }
    report["verdict"] = review_verdict(report)
    (run_root / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return run_root


def smoke() -> dict[str, Any]:
    root = Path(__file__).parents[2]
    report = json.loads(
        (root / "tests" / "fixtures" / "pilot-report.json").read_text(encoding="utf-8")
    )
    validate_report(report)
    if review_verdict(report) != "continue":
        raise PilotError("fixture should support continue")
    for session in SESSIONS:
        parse_codex_jsonl(root / "tests" / "fixtures" / f"pilot-{session}.jsonl", session)
    return {"status": "ok", "verdict": "continue"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="outctl pilot")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("smoke", help="validate offline fixture evidence")
    validate = subparsers.add_parser("validate", help="validate a metadata-only report")
    validate.add_argument("report", type=Path)
    telemetry_probe = subparsers.add_parser(
        "telemetry-probe", help="validate a pinned app-server token telemetry schema"
    )
    telemetry_probe.add_argument("schema", type=Path)
    launch_parser = subparsers.add_parser("launch", help="run the read-only concurrent pilot")
    launch_parser.add_argument("--appservice", required=True)
    launch_parser.add_argument("--kubeconfig", required=True)
    launch_parser.add_argument("--context", required=True)
    launch_parser.add_argument("--namespace", required=True)
    launch_parser.add_argument("--output", type=Path, default=Path(".outctl-pilot"))
    args = parser.parse_args(argv)
    try:
        if args.command == "smoke":
            print(json.dumps(smoke(), sort_keys=True))
        elif args.command == "validate":
            report = json.loads(args.report.read_text(encoding="utf-8"))
            validate_report(report)
            print(json.dumps({"status": "ok", "verdict": review_verdict(report)}, sort_keys=True))
        elif args.command == "telemetry-probe":
            validate_app_server_schema(args.schema)
            print(json.dumps({"status": "ok", "telemetry": "app-server-token-usage"}))
        else:
            print(launch(args))
    except (OSError, json.JSONDecodeError, PilotError) as exc:
        print(f"outctl pilot: {exc}", file=sys.stderr)
        return 2
    return 0
