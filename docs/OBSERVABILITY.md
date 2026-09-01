# Agent observability and experiment reporting

`outctl` owns the event shape and the semantic comparison boundary. Appservice
owns deployment of the boring telemetry plumbing. The intended production path
is:

```text
runner / harness
      │ structured, raw-free events
      ▼
outctl local JSONL ──► OTLP/HTTP Collector ──► Prometheus
          │                         └────────► Loki
          └──────────────► deterministic HLA experiment report
```

No provider SDK or observability daemon is required for local operation. The
same event stream can be retained locally, rendered as Prometheus text, pushed
to Loki, or sent to an appservice-provided OpenTelemetry Collector.

## Event contract

Use `TelemetryContext` for the bounded analysis dimensions and the correlation
identifiers. A recorder emits `run_started`, `model_request`, `tool_result`,
and `run_completed` events. Events carry measurements only; prompts,
responses, transcripts, command bodies, and raw output are rejected.

The following dimensions are allowed as Prometheus labels:

```text
experiment, arm, provider, model, harness, scenario
```

`run_id`, `session_id`, `correlation_id`, and `tool` remain structured event
fields. This is what allows Loki/HLA to reconstruct interaction topology without
turning Prometheus into a UUID or tool-name database.

## Local collection

```python
from pathlib import Path

from outctl import JsonlEventSink, TelemetryContext, TelemetryRecorder

context = TelemetryContext(
    experiment="outctl-long-horizon-v2",
    arm="treatment",
    run_id="01K...",
    session_id="session-1",
    provider="anthropic",
    model="claude-sonnet-5",
    harness="codex",
    scenario="database-no-endpoints",
)

with JsonlEventSink(Path(".outctl/observability/events.ndjson")) as sink:
    telemetry = TelemetryRecorder(context, [sink])
    telemetry.run_started()
    telemetry.model_request(input_tokens=2819, output_tokens=183, cached_tokens=0)
    telemetry.tool_result(tool="kubectl", duration_ms=438, visible_bytes=22000, success=True)
    telemetry.run_completed(result="pass", duration_ms=16000, active_time_ms=12000)
```

The local directory is mode `0700` and the event file is mode `0600`.

## Export

Render a Prometheus textfile for a node-exporter textfile collector or an
equivalent appservice scrape path:

```bash
outctl telemetry export .outctl/observability/events.ndjson \
  --format prometheus \
  --output .outctl/observability/agent.prom
```

Build a Loki push payload or send it to the base URL supplied by appservice:

```bash
outctl telemetry export .outctl/observability/events.ndjson --format loki
outctl telemetry export .outctl/observability/events.ndjson \
  --format loki --endpoint https://loki.example.invalid
```

The Loki endpoint must be a base URL; the exporter appends
`/loki/api/v1/push`. OTLP export similarly appends `/v1/logs` and
`/v1/metrics` to the Collector base URL:

```bash
outctl telemetry export .outctl/observability/events.ndjson \
  --format otlp-logs --endpoint https://otel-collector.example.invalid
```

The `otlp-logs` and `otlp-metrics` renderings are OTLP/HTTP JSON. A network
export sends both signals together so the Collector can route logs to Loki and
metrics to Prometheus.

## Experiment reports

The report compiler is intentionally separate from collection. A new
experiment changes the YAML definition and tags, not the measurement harness:

```bash
outctl experiment compare \
  examples/observability/outctl-long-horizon-v2.yaml \
  .outctl/observability/events.ndjson > report.json
```

The output includes per-arm count/sum/mean/median/stdev/variance, absolute and
relative deltas, outcome pass rates, model-decision boundaries, tools per model round,
tokens/cost per successful run, visible evidence bytes, and a collapsed
`model → tool → model` interaction topology. It is raw-free and carries a
content digest for handoff to Homelab Analytics.

The example can be run offline:

```bash
outctl telemetry validate examples/observability/events.ndjson
outctl experiment compare examples/observability/outctl-long-horizon-v2.yaml \
  examples/observability/events.ndjson
```

For the existing app-server pilot artifact, migrate its bounded measurements
before comparing it:

```bash
outctl telemetry from-pilot pilot-report.json --experiment pilot-v1 \
  --provider anthropic --model claude-sonnet-5 \
  --output .outctl/observability/pilot-events.ndjson
```

Grafana remains the operational UI. Homelab Analytics consumes the bounded
Prometheus/Loki views and owns the question-specific conclusion. Tempo is not
required by this slice; it can be added later when cross-service nested spans
or distributed critical-path analysis justify it.
