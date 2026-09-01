"""Read-only, binary-safe command-line access to local captures."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from outctl import __version__, pilot
from outctl.adapter import (
    AdapterIdentity,
    AdapterMode,
    AdapterRequest,
    resolve_adapter_mode,
    run_adapter,
)
from outctl.benchmark import benchmark, rollback_check
from outctl.capture import recover_partials
from outctl.contracts import ContractValidationError, validate_contract
from outctl.control import (
    commissioning_context_from_dict,
    compile_policy_source,
    explain_policy,
    lint_policy_source,
)
from outctl.enablement import EnablementEvidenceError, evaluate_enablement
from outctl.enforcement import (
    EnforcementError,
    compile_enforcement_observation,
    select_command_mode,
)
from outctl.observability import (
    ObservabilityError,
    build_loki_push,
    build_otlp_logs,
    build_otlp_metrics,
    compare_experiment,
    events_from_pilot_report,
    export_loki,
    export_otlp,
    load_document,
    read_events,
    render_prometheus,
)
from outctl.pilot import PilotReportError, validate_pilot_report
from outctl.projection import ProjectionLimits, ProjectionResult, project_bytes
from outctl.retrieval import (
    InspectionResult,
    RetrievalStatus,
    SearchResult,
    SliceResult,
    TailResult,
    VerificationResult,
    inspect_capture,
    search_stream,
    slice_stream,
    tail_stream,
    verify_capture,
)
from outctl.serialization import canonical_json_text
from outctl.study import StudyCompileError, compile_study_analysis, load_json_object
from outctl.ux import UxCompileError, compile_ux_evidence

_DEFAULT_SPOOL = Path(".outctl")
_DEFAULT_MAX_BYTES = 64 * 1024
_MAX_METADATA_TEXT = 512


def _spool_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--spool-root",
        type=Path,
        default=_DEFAULT_SPOOL,
        help="local outctl spool root (default: .outctl)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="outctl",
        description="Bounded, recoverable command-output retrieval",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")

    run = commands.add_parser("run", help="run direct argv with an opt-in capture boundary")
    _spool_argument(run)
    run.add_argument("--mode", choices=tuple(mode.value for mode in AdapterMode))
    run.add_argument("--policy-ref", default="interactive-default-v1")
    run.add_argument("--policy-digest", default="sha256:" + "0" * 64)
    run.add_argument("--max-capture-bytes", type=int, default=16 * 1024 * 1024)
    run.add_argument("--max-projection-bytes", type=int, default=_DEFAULT_MAX_BYTES)
    run.add_argument("--max-projection-lines", type=int, default=2_000)
    run.add_argument("--max-projection-tokens", type=int, default=16_000)
    run.add_argument("--timeout", type=float)
    run.add_argument("--cwd", type=Path)
    run.add_argument("argv", nargs=argparse.REMAINDER, help="command after --")

    inspect = commands.add_parser("inspect", help="inspect capture metadata")
    _spool_argument(inspect)
    inspect.add_argument("capture_id")

    slice_parser = commands.add_parser("slice", help="project a byte range safely")
    _spool_argument(slice_parser)
    slice_parser.add_argument("capture_id")
    slice_parser.add_argument("stream", choices=("stdout", "stderr"))
    slice_parser.add_argument("start", type=int)
    slice_parser.add_argument("end", type=int)
    slice_parser.add_argument("--max-bytes", type=int, default=_DEFAULT_MAX_BYTES)

    tail = commands.add_parser("tail", help="project a stream suffix safely")
    _spool_argument(tail)
    tail.add_argument("capture_id")
    tail.add_argument("stream", choices=("stdout", "stderr"))
    tail.add_argument("--lines", type=int)
    tail.add_argument("--max-bytes", type=int, default=_DEFAULT_MAX_BYTES)

    search = commands.add_parser("search", help="search a stream without rerunning it")
    _spool_argument(search)
    search.add_argument("capture_id")
    search.add_argument("stream", choices=("stdout", "stderr"))
    search.add_argument("pattern")
    search.add_argument("--regex", action="store_true")
    search.add_argument("--context-bytes", type=int, default=80)
    search.add_argument("--max-matches", type=int, default=20)

    search_many = commands.add_parser(
        "search-many", help="batch literal searches against one existing capture"
    )
    _spool_argument(search_many)
    search_many.add_argument("capture_id")
    search_many.add_argument("stream", choices=("stdout", "stderr"))
    search_many.add_argument("patterns", nargs="+")
    search_many.add_argument("--context-bytes", type=int, default=80)
    search_many.add_argument("--max-matches-per-pattern", type=int, default=3)

    verify = commands.add_parser("verify", help="verify capture digests")
    _spool_argument(verify)
    verify.add_argument("capture_id")

    recover = commands.add_parser("recover", help="mark abandoned partial captures")
    _spool_argument(recover)

    gc = commands.add_parser("gc", help="list garbage-collection candidates")
    _spool_argument(gc)
    gc.add_argument("--dry-run", action="store_true", required=True)

    pilot_validate = commands.add_parser(
        "pilot-validate", help="validate a raw-free qualitative pilot report"
    )
    pilot_validate.add_argument("report", type=Path)
    pilot_command = commands.add_parser("pilot", help="concurrent Terra pilot tooling")
    pilot_command.add_argument("pilot_args", nargs=argparse.REMAINDER)
    mechanism = commands.add_parser("benchmark", help="run the model-free mechanism benchmark")
    _spool_argument(mechanism)
    mechanism.add_argument("--repetitions", type=int, default=1)
    mechanism.add_argument("--scale", type=int, default=20_000)
    mechanism.add_argument("--max-projection-bytes", type=int, default=4_096)
    enablement = commands.add_parser("enablement", help="evaluate metadata-only stage gates")
    enablement.add_argument("evidence", type=Path)
    commands.add_parser("rollback-check", help="verify break-glass bypass locally")
    contract = commands.add_parser("contract-validate", help="validate a shared JSON contract")
    contract.add_argument(
        "schema",
        choices=(
            "cross-harness-conformance",
            "approved-command-policy",
            "enablement-evidence",
            "enforcement-observation",
            "evidence-reference",
            "experiment-definition",
            "experiment-report",
            "expected-facts",
            "logical-command-request",
            "observability-event",
            "runner-command-result",
            "scenario-manifest",
            "shadow-observation",
            "study-analysis",
            "study-protocol",
            "study-suite",
            "ux-evidence",
        ),
    )
    contract.add_argument("document", type=Path)
    study_compile = commands.add_parser(
        "study-compile", help="compile raw-free paired study observations"
    )
    study_compile.add_argument("protocol", type=Path)
    study_compile.add_argument("observations", type=Path)
    telemetry = commands.add_parser(
        "telemetry", help="validate and export bounded agent observability events"
    )
    telemetry_commands = telemetry.add_subparsers(dest="telemetry_command", required=True)
    telemetry_validate = telemetry_commands.add_parser("validate", help="validate event JSONL")
    telemetry_validate.add_argument("events", type=Path)
    pilot_events = telemetry_commands.add_parser(
        "from-pilot", help="convert an existing raw-free pilot report to event JSONL"
    )
    pilot_events.add_argument("report", type=Path)
    pilot_events.add_argument("--experiment", required=True, dest="experiment_id")
    pilot_events.add_argument("--baseline-session", default="B")
    pilot_events.add_argument("--treatment-session", default="A")
    pilot_events.add_argument("--provider", default="unknown")
    pilot_events.add_argument("--model", default="unknown")
    pilot_events.add_argument("--harness", default="codex")
    pilot_events.add_argument("--scenario", default="pilot")
    pilot_events.add_argument("--output", type=Path, required=True)
    telemetry_export = telemetry_commands.add_parser("export", help="export event JSONL")
    telemetry_export.add_argument("events", type=Path)
    telemetry_export.add_argument(
        "--format", choices=("prometheus", "loki", "otlp-logs", "otlp-metrics"), required=True
    )
    telemetry_export.add_argument("--endpoint", help="appservice endpoint for network export")
    telemetry_export.add_argument(
        "--output", type=Path, help="write the rendered payload to a file"
    )
    experiment = commands.add_parser("experiment", help="compile Homelab Analytics reports")
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)
    experiment_compare = experiment_commands.add_parser(
        "compare", help="compare baseline and treatment event runs"
    )
    experiment_compare.add_argument("definition", type=Path)
    experiment_compare.add_argument("events", type=Path)
    # Keep a flat spelling for scripts while the nested form mirrors HLA's
    # proposed `experiment compare` command.
    flat_compare = commands.add_parser("experiment-compare", help=argparse.SUPPRESS)
    flat_compare.add_argument("definition", type=Path)
    flat_compare.add_argument("events", type=Path)
    ux_compile = commands.add_parser("ux-compile", help="compile digest-bound UX evidence")
    ux_compile.add_argument("task_protocol", type=Path)
    ux_compile.add_argument("observations", type=Path)
    selector = commands.add_parser(
        "enforcement-select", help="select mode for an approved command class"
    )
    selector.add_argument("policy", type=Path)
    selector.add_argument("command_class")
    enforcement_compile = commands.add_parser(
        "enforcement-compile", help="compile selected enforcement evidence"
    )
    enforcement_compile.add_argument("policy", type=Path)
    enforcement_compile.add_argument("observation", type=Path)
    policy = commands.add_parser("policy", help="compile and inspect W5 trust policy")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    for name in ("lint", "explain"):
        policy_command = policy_commands.add_parser(
            name, help=f"{name} a root-confined W5 policy source"
        )
        policy_command.add_argument("--policy-root", type=Path, required=True)
        policy_command.add_argument("--context", type=Path, required=True)
        policy_command.add_argument("source", type=Path)
    return parser


def _json(value: Mapping[str, Any]) -> None:
    """Emit ASCII JSON so metadata cannot control the caller's terminal."""
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def _record_retrieval(spool_root: Path, capture_id: str, operation: str) -> None:
    """Append raw-free local evidence that a retrieval read an existing capture."""
    spool_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(spool_root, 0o700)
    event_path = spool_root / "retrieval-events.jsonl"
    descriptor = os.open(event_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(
            descriptor,
            (
                json.dumps({"capture_id": capture_id, "operation": operation}, sort_keys=True)
                + "\n"
            ).encode(),
        )
    finally:
        os.close(descriptor)


def _record_command(spool_root: Path, capture_id: str, executable: str) -> None:
    event_path = spool_root / "command-events.jsonl"
    descriptor = os.open(event_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(
            descriptor,
            (
                json.dumps({"capture_id": capture_id, "executable": executable}, sort_keys=True)
                + "\n"
            ).encode(),
        )
    finally:
        os.close(descriptor)


def _metadata_text(value: object) -> str | None:
    """Keep error and manifest strings bounded before serializing them."""
    if not isinstance(value, str):
        return None
    return value[:_MAX_METADATA_TEXT]


def _status_code(status: RetrievalStatus) -> int:
    return 0 if status is RetrievalStatus.AVAILABLE else 1


def _safe_projection(data: bytes, max_bytes: int) -> ProjectionResult:
    # Retrieval byte limits and model-exposure limits are separate.  This
    # second cap ensures a response remains safe if the retrieval API evolves.
    limit = max(1, min(max_bytes, _DEFAULT_MAX_BYTES))
    return project_bytes(data, limits=ProjectionLimits(limit, 2_000, 16_000))


def _projection_data(data: bytes, max_bytes: int) -> dict[str, object]:
    projection = _safe_projection(data, max_bytes)
    return {
        "text": projection.text,
        "bytes": projection.bytes,
        "lines": projection.lines,
        "estimated_tokens": projection.estimated_tokens,
        "lossy": projection.lossy,
        "normalized": projection.normalized,
        "redacted": projection.redacted,
        "sha256": projection.sha256,
        "gap_marker": projection.gap_marker,
    }


def _inspection_payload(result: InspectionResult) -> dict[str, object]:
    """Expose a compact allowlist, never arbitrary manifest contents."""
    payload: dict[str, object] = {
        "status": result.status.value,
        "capture_id": result.capture_id,
        "capture_status": _metadata_text(result.capture_status),
        "detail": _metadata_text(result.detail),
    }
    manifest = result.manifest
    if manifest is not None:
        streams = manifest.get("streams")
        event_index = manifest.get("event_index")
        payload["metadata"] = {
            "stdout_bytes": _nested_int(streams, "stdout", "bytes"),
            "stderr_bytes": _nested_int(streams, "stderr", "bytes"),
            "event_count": event_index.get("events")
            if isinstance(event_index, dict) and isinstance(event_index.get("events"), int)
            else None,
        }
        payload["outline"] = {
            "streams": ["stdout", "stderr"],
            "retrieval_operations": ["slice", "tail", "search", "search-many"],
            "omission_reasons": (
                ["capture_quota"]
                if result.capture_status in {"CAPTURE_TRUNCATED", "CAPTURE_DEGRADED"}
                else []
            ),
        }
    return payload


def _nested_int(value: object, key: str, nested_key: str) -> int | None:
    entry = value.get(key) if isinstance(value, dict) else None
    result = entry.get(nested_key) if isinstance(entry, dict) else None
    return result if isinstance(result, int) else None


def _slice_payload(result: SliceResult, max_bytes: int) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": result.status.value,
        "capture_id": result.capture_id,
        "stream": result.stream,
        "start": result.start,
        "end": result.end,
        "detail": _metadata_text(result.detail),
    }
    if result.status is RetrievalStatus.AVAILABLE:
        payload["projection"] = _projection_data(result.data, max_bytes)
    return payload


def _tail_payload(result: TailResult, max_bytes: int) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": result.status.value,
        "capture_id": result.capture_id,
        "stream": result.stream,
        "truncated": result.truncated,
        "detail": _metadata_text(result.detail),
    }
    if result.status is RetrievalStatus.AVAILABLE:
        payload["projection"] = _projection_data(result.data, max_bytes)
    return payload


def _search_payload(result: SearchResult) -> dict[str, object]:
    matches: list[dict[str, object]] = []
    for match in result.matches:
        matches.append(
            {
                "start": match.start,
                "end": match.end,
                "projection": _projection_data(match.context, 4 * 1024),
            }
        )
    return {
        "status": result.status.value,
        "capture_id": result.capture_id,
        "stream": result.stream,
        "matches": matches,
        "limited": result.limited,
        "detail": _metadata_text(result.detail),
    }


def _verification_payload(result: VerificationResult) -> dict[str, object]:
    return {
        "status": result.status.value,
        "capture_id": result.capture_id,
        "checks": [
            {
                "artifact": check.artifact,
                "expected": check.expected,
                "observed": check.observed,
                "matches": check.matches,
            }
            for check in result.checks
        ],
        "detail": _metadata_text(result.detail),
    }


def _gc_candidates(root: Path) -> list[str]:
    captures = root / "captures"
    try:
        return sorted(
            path.name for path in captures.iterdir() if path.is_dir() and not path.is_symlink()
        )
    except OSError:
        return []


def _command_exit_code(exit_code: int | None, signal_number: int | None) -> int:
    if exit_code is not None:
        return exit_code
    return 128 + signal_number if signal_number is not None else 1


def _run_payload(args: argparse.Namespace) -> tuple[dict[str, object], int]:
    argv = list(args.argv)
    if argv[:1] == ["--"]:
        argv.pop(0)
    if not argv:
        raise ValueError("run requires direct argv after --")
    configured_mode = AdapterMode(args.mode) if args.mode is not None else None
    mode = resolve_adapter_mode(configured_mode, default=AdapterMode.ENFORCE)
    result = asyncio.run(
        run_adapter(
            AdapterRequest(
                mode=mode,
                argv=argv,
                policy_ref=args.policy_ref,
                policy_digest=args.policy_digest,
                identity=AdapterIdentity(host_id=socket.gethostname(), harness="outctl-cli"),
                spool_root=args.spool_root,
                cwd=args.cwd,
                timeout=args.timeout,
                max_capture_bytes=args.max_capture_bytes,
                projection_limits=ProjectionLimits(
                    args.max_projection_bytes,
                    args.max_projection_lines,
                    args.max_projection_tokens,
                ),
            )
        )
    )
    payload: dict[str, object] = {
        "mode": result.mode.value,
        "command": {
            "exit_code": result.command.exit_code,
            "signal": result.command.signal,
            "timed_out": result.command.timed_out,
            "cancelled": result.command.cancelled,
        },
    }
    if result.envelope is not None:
        payload["envelope"] = result.envelope.to_dict()
    if result.receipt is not None:
        payload["receipt"] = result.receipt
    return payload, _command_exit_code(result.command.exit_code, result.command.signal)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        return 0
    try:
        if args.command == "run":
            payload, exit_code = _run_payload(args)
            receipt = payload.get("receipt")
            if isinstance(receipt, dict) and isinstance(receipt.get("capture_id"), str):
                argv = list(args.argv)
                if argv[:1] == ["--"]:
                    argv.pop(0)
                if argv:
                    _record_command(args.spool_root, receipt["capture_id"], Path(argv[0]).name)
            _json(payload)
            return exit_code
        if args.command == "inspect":
            inspection = inspect_capture(args.spool_root, args.capture_id)
            if inspection.status is RetrievalStatus.AVAILABLE:
                _record_retrieval(args.spool_root, args.capture_id, "inspect")
            _json(_inspection_payload(inspection))
            return _status_code(inspection.status)
        if args.command == "slice":
            sliced = slice_stream(
                args.spool_root,
                args.capture_id,
                args.stream,
                args.start,
                args.end,
                max_bytes=args.max_bytes,
            )
            if sliced.status is RetrievalStatus.AVAILABLE:
                _record_retrieval(args.spool_root, args.capture_id, "slice")
            _json(_slice_payload(sliced, args.max_bytes))
            return _status_code(sliced.status)
        if args.command == "tail":
            tailed = tail_stream(
                args.spool_root,
                args.capture_id,
                args.stream,
                lines=args.lines,
                max_bytes=args.max_bytes,
            )
            if tailed.status is RetrievalStatus.AVAILABLE:
                _record_retrieval(args.spool_root, args.capture_id, "tail")
            _json(_tail_payload(tailed, args.max_bytes))
            return _status_code(tailed.status)
        if args.command == "search":
            searched = search_stream(
                args.spool_root,
                args.capture_id,
                args.stream,
                args.pattern,
                regex=args.regex,
                context_bytes=args.context_bytes,
                max_matches=args.max_matches,
            )
            if searched.status is RetrievalStatus.AVAILABLE:
                _record_retrieval(args.spool_root, args.capture_id, "search")
            _json(_search_payload(searched))
            return _status_code(searched.status)
        if args.command == "search-many":
            if len(args.patterns) > 8:
                raise ValueError("search-many accepts at most 8 literal patterns")
            if not 1 <= args.max_matches_per_pattern <= 3:
                raise ValueError("--max-matches-per-pattern must be between 1 and 3")
            results = [
                search_stream(
                    args.spool_root,
                    args.capture_id,
                    args.stream,
                    pattern,
                    context_bytes=args.context_bytes,
                    max_matches=args.max_matches_per_pattern,
                )
                for pattern in args.patterns
            ]
            available = all(result.status is RetrievalStatus.AVAILABLE for result in results)
            if available:
                _record_retrieval(args.spool_root, args.capture_id, "search-many")
            _json(
                {
                    "status": "AVAILABLE" if available else "UNAVAILABLE",
                    "capture_id": args.capture_id,
                    "stream": args.stream,
                    "queries": [
                        {"pattern": pattern, **_search_payload(result)}
                        for pattern, result in zip(args.patterns, results, strict=True)
                    ],
                }
            )
            return 0 if available else 1
        if args.command == "verify":
            verified = verify_capture(args.spool_root, args.capture_id)
            _json(_verification_payload(verified))
            return _status_code(verified.status)
        if args.command == "recover":
            records = recover_partials(args.spool_root)
            _json(
                {
                    "status": "RECOVERED",
                    "captures": [
                        {"capture_id": record.capture_id, "status": record.status}
                        for record in records
                    ],
                }
            )
            return 0
        if args.command == "gc":
            _json(
                {
                    "status": "DRY_RUN",
                    "dry_run": True,
                    "candidates": _gc_candidates(args.spool_root),
                    "deleted": [],
                }
            )
            return 0
        if args.command == "pilot-validate":
            with args.report.open(encoding="utf-8") as report_file:
                report = json.load(report_file)
            if not isinstance(report, dict):
                raise ValueError("pilot report must be a JSON object")
            summary = validate_pilot_report(report)
            _json(
                {
                    "status": "VALID",
                    "harness": summary.harness,
                    "command_class": summary.command_class,
                    "policy_digest": summary.policy_digest,
                    "baseline_exposed_tokens": summary.baseline_exposed_tokens,
                    "enforce_exposed_tokens": summary.enforce_exposed_tokens,
                    "retrieval_count": summary.retrieval_count,
                }
            )
            return 0
        if args.command == "pilot":
            return pilot.main(args.pilot_args)
        if args.command == "benchmark":
            report = benchmark(
                args.spool_root,
                repetitions=args.repetitions,
                scale=args.scale,
                max_projection_bytes=args.max_projection_bytes,
            )
            _json(report)
            return 0 if report["passed"] is True else 1
        if args.command == "enablement":
            value = json.loads(args.evidence.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise EnablementEvidenceError("enablement evidence root must be an object")
            _json(evaluate_enablement(value))
            return 0
        if args.command == "rollback-check":
            report = rollback_check()
            _json(report)
            return 0 if report["passed"] is True else 1
        if args.command == "contract-validate":
            value = json.loads(args.document.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ContractValidationError("contract document root must be an object")
            validate_contract(args.schema, value)
            _json({"status": "VALID", "schema": args.schema})
            return 0
        if args.command == "study-compile":
            _json(
                compile_study_analysis(
                    load_json_object(args.protocol), load_json_object(args.observations)
                )
            )
            return 0
        if args.command == "telemetry":
            if args.telemetry_command == "from-pilot":
                report = load_document(args.report)
                events = events_from_pilot_report(
                    report,
                    experiment_id=args.experiment_id,
                    baseline_session=args.baseline_session,
                    treatment_session=args.treatment_session,
                    provider=args.provider,
                    model=args.model,
                    harness=args.harness,
                    scenario=args.scenario,
                )
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(
                    "".join(canonical_json_text(event.to_dict()) + "\n" for event in events),
                    encoding="utf-8",
                )
                args.output.chmod(0o600)
                _json({"status": "WRITTEN", "events": len(events), "path": str(args.output)})
                return 0
            events = read_events(args.events)
            if args.telemetry_command == "validate":
                _json(
                    {
                        "status": "VALID",
                        "schema": "observability-event",
                        "events": len(events),
                        "runs": len({event.context.run_id for event in events}),
                    }
                )
                return 0
            if args.telemetry_command == "export":
                if args.format == "prometheus":
                    rendered = render_prometheus(events)
                elif args.format == "loki":
                    rendered = json.dumps(
                        build_loki_push(events), sort_keys=True, separators=(",", ":")
                    )
                elif args.format == "otlp-logs":
                    rendered = json.dumps(
                        build_otlp_logs(events), sort_keys=True, separators=(",", ":")
                    )
                else:
                    rendered = json.dumps(
                        build_otlp_metrics(events), sort_keys=True, separators=(",", ":")
                    )
                if args.endpoint:
                    if args.format == "loki":
                        export_loki(events, args.endpoint)
                    elif args.format in {"otlp-logs", "otlp-metrics"}:
                        export_otlp(events, args.endpoint)
                    else:
                        raise ObservabilityError(
                            "Prometheus export has no push endpoint; use --output or scrape it"
                        )
                    _json({"status": "EXPORTED", "format": args.format, "events": len(events)})
                elif args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(rendered, encoding="utf-8")
                    args.output.chmod(0o600)
                    _json({"status": "WRITTEN", "format": args.format, "path": str(args.output)})
                elif args.format == "prometheus":
                    print(rendered, end="")
                else:
                    print(rendered)
                return 0
            raise AssertionError(f"unknown telemetry command {args.telemetry_command!r}")
        if args.command in {"experiment", "experiment-compare"}:
            definition = load_document(args.definition)
            events = read_events(args.events)
            _json(compare_experiment(definition, events))
            return 0
        if args.command == "ux-compile":
            _json(
                compile_ux_evidence(
                    load_json_object(args.task_protocol), load_json_object(args.observations)
                )
            )
            return 0
        if args.command == "enforcement-select":
            _json(select_command_mode(load_json_object(args.policy), args.command_class))
            return 0
        if args.command == "enforcement-compile":
            _json(
                compile_enforcement_observation(
                    load_json_object(args.policy), load_json_object(args.observation)
                )
            )
            return 0
        if args.command == "policy":
            context_value = load_json_object(args.context)
            context = commissioning_context_from_dict(context_value)
            if args.policy_command == "lint":
                result = lint_policy_source(args.policy_root, args.source, context)
                _json(result.to_dict())
                return 0 if result.valid else 2
            if args.policy_command == "explain":
                compiled = compile_policy_source(args.policy_root, args.source, context)
                _json(explain_policy(compiled).to_dict())
                return 0
            raise AssertionError(f"unknown policy command {args.policy_command!r}")
    except (
        EnforcementError,
        OSError,
        ObservabilityError,
        PilotReportError,
        StudyCompileError,
        UxCompileError,
        ValueError,
    ) as error:
        _json({"status": "ERROR", "detail": _metadata_text(str(error))})
        return 2
    raise AssertionError(f"unknown command {args.command!r}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
