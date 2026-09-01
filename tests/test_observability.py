from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from outctl.observability import (
    ObservabilityError,
    TelemetryContext,
    TelemetryEvent,
    TelemetryRecorder,
    build_loki_push,
    build_otlp_logs,
    compare_experiment,
    events_from_pilot_report,
    render_prometheus,
)


def _run(
    arm: str,
    run_id: str,
    *,
    input_tokens: int,
    output_tokens: int,
    tool_calls: int,
    visible_bytes: int,
    result: str = "pass",
) -> list[TelemetryEvent]:
    context = TelemetryContext(
        experiment="outctl-long-horizon-v2",
        arm=arm,
        run_id=run_id,
        session_id=f"session-{run_id}",
        provider="anthropic",
        model="claude-sonnet-5",
        harness="codex",
        scenario="database-no-endpoints",
    )
    recorder = TelemetryRecorder(context, clock=lambda: "2026-08-16T00:00:00Z")
    values: list[dict[str, object]] = [recorder.run_started()]
    for index in range(tool_calls):
        values.append(
            recorder.model_request(input_tokens=input_tokens, output_tokens=output_tokens)
        )
        values.append(
            recorder.tool_result(
                tool="kubectl",
                duration_ms=400 + index,
                visible_bytes=visible_bytes,
                success=index != tool_calls - 1 or result == "pass",
            )
        )
    values.append(
        recorder.run_completed(
            result=result,
            duration_ms=12_000,
            active_time_ms=6_000,
            cost_usd=0.12,
            lines_changed=4,
        )
    )
    return [TelemetryEvent.from_dict(value) for value in values]


def test_prometheus_labels_are_bounded_and_ids_stay_out_of_labels() -> None:
    events = _run(
        "treatment", "run-uuid-1", input_tokens=10, output_tokens=2, tool_calls=2, visible_bytes=20
    )
    rendered = render_prometheus(events)

    assert 'agent_tokens_total{arm="treatment"' in rendered
    assert 'token_type="input"' in rendered
    assert "run-uuid-1" not in rendered
    assert "session-run-uuid-1" not in rendered
    assert "tool=" not in rendered


def test_loki_and_otlp_keep_correlation_ids_as_event_data() -> None:
    events = _run(
        "baseline", "run-1", input_tokens=10, output_tokens=2, tool_calls=1, visible_bytes=20
    )
    loki = build_loki_push(events)
    assert "run_id" not in loki["streams"][0]["stream"]
    assert any("run-1" in entry[1] for entry in loki["streams"][0]["values"])

    logs = build_otlp_logs(events)
    record = logs["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert {item["key"] for item in record["attributes"]} >= {"run.id", "session.id"}


def test_compare_report_reconstructs_topology_and_derived_metrics() -> None:
    events = [
        *_run(
            "baseline",
            "b-1",
            input_tokens=100,
            output_tokens=20,
            tool_calls=1,
            visible_bytes=439_000,
        ),
        *_run(
            "treatment",
            "t-1",
            input_tokens=110,
            output_tokens=18,
            tool_calls=3,
            visible_bytes=22_000,
        ),
    ]
    report = compare_experiment(
        {
            "id": "outctl-long-horizon-v2",
            "baseline": "baseline",
            "treatment": "treatment",
            "metrics": ["tokens.input", "tokens.output", "duration", "tool_calls"],
            "derived": [
                "model_decision_boundaries",
                "tools_per_model_round",
                "interaction_topology",
            ],
        },
        events,
    )

    assert report["metrics"]["tokens.input"]["baseline"]["mean"] == 100
    assert report["metrics"]["tokens.input"]["delta"]["relative_pct"] == pytest.approx(230)
    assert report["derived"]["model_decision_boundaries"]["treatment"]["mean"] == 3
    assert report["derived"]["tools_per_model_round"]["treatment"]["mean"] == 1
    assert report["derived"]["interaction_topology"]["treatment"] == {
        "model→tool→model→tool→model→tool": 1
    }
    assert report["outcome"]["treatment"]["pass_rate"] == 1


def test_experiment_definition_accepts_hla_nested_shape() -> None:
    report = compare_experiment(
        {
            "experiment": {"id": "exp", "baseline": "direct", "treatment": "outctl"},
            "metrics": ["outcome"],
        },
        [],
    )
    assert report["experiment_id"] == "exp"


def test_event_schema_rejects_raw_body_and_unbounded_prometheus_dimensions() -> None:
    context = TelemetryContext("exp", "arm", "run/id", "session/id")
    assert "run_id" not in context.labels()
    with pytest.raises(ObservabilityError, match="unsupported telemetry fields"):
        TelemetryEvent(context, "run_started", 0, "2026-08-16T00:00:00Z", {"body": "secret"})
    with pytest.raises(ObservabilityError, match="control character"):
        TelemetryContext("exp", "arm", "run", "session", scenario="case\nwith\nnewline")


def test_event_and_report_schemas_accept_generated_documents() -> None:
    root = Path(__file__).parents[1]
    event = _run(
        "baseline", "r-1", input_tokens=1, output_tokens=1, tool_calls=1, visible_bytes=1
    )[0]
    event_schema = json.loads((root / "schemas/observability-event.schema.json").read_text())
    jsonschema.Draft202012Validator(event_schema).validate(event.to_dict())
    report = compare_experiment(
        {"id": "exp", "baseline": "baseline", "treatment": "treatment", "metrics": ["cost"]},
        [],
    )
    report_schema = json.loads((root / "schemas/experiment-report.schema.json").read_text())
    jsonschema.Draft202012Validator(report_schema).validate(report)


def test_existing_pilot_report_can_be_migrated_without_raw_fields() -> None:
    report = json.loads(
        (Path(__file__).parent / "fixtures" / "pilot-report.json").read_text(encoding="utf-8")
    )
    events = events_from_pilot_report(
        report,
        experiment_id="pilot-v1",
        provider="anthropic",
        model="claude-sonnet-5",
    )
    assert len(events) == 14
    assert {event.context.arm for event in events} == {"baseline", "treatment"}
    assert all("argv" not in event.to_dict() for event in events)
