# outctl discovery artifact

**Working component name:** `outctl`  
**Status:** **KILLED — frozen discovery artifact; maintenance-only**
**Decision:** 2026-08-16

This repository is no longer an active Vuoro product. It preserves the
implementation, experiments, and acceptance material that tested bounded
command-output capture so the work can be reproduced or compared later. Do not
start new feature work here.

The replacement hypothesis is documented in
[`docs/DISCOVERY_KILL_2026-08-16.md`](docs/DISCOVERY_KILL_2026-08-16.md): use a
thin harness capture adapter, standard OpenTelemetry, Langfuse or Phoenix,
and object storage for large pre-discard tool results. Native harnesses own
execution and reduction. Existing observability infrastructure owns traces,
sessions, search, UI, retention, and most retrieval.

`outctl` is not a scheduler, queue, workflow engine, shell, model router,
knowledge store, observability backend, or alternate Vuoro control plane.

## Recommended reading order

1. [`docs/DISCOVERY_KILL_2026-08-16.md`](docs/DISCOVERY_KILL_2026-08-16.md) —
   decision record, evidence, and the one remaining triage hypothesis.
2. [`docs/DESIGN.md`](docs/DESIGN.md) and
   [`acceptance/SCENARIOS.md`](acceptance/SCENARIOS.md) — normative Python v1
   compatibility baseline retained for historical context.
3. [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and the accepted ADRs under
   [`docs/adr/`](docs/adr/).
4. [`docs/ENABLEMENT_PLAN.md`](docs/ENABLEMENT_PLAN.md) and
   [`docs/CONTRACT_INTEGRATION.md`](docs/CONTRACT_INTEGRATION.md) — existing
   pilot and ecosystem integration records, now subordinate to the kill
   decision.

## Historical architecture

The implementation tested a native runner or model harness passing completed
stdout/stderr artifacts to `outctl`, which stored a verified capture and wrote
a raw-free observation record. This remains available only as a historical
control.

```text
native harness -> thin capture adapter -> OTLP -> Langfuse/Phoenix
                                      \-> MinIO/S3 immutable artifact
```

The diagram above is the replacement direction, not an implementation claim
made by this repository.

## Package contents

- `docs/DESIGN.md`: full design.
- `schemas/output-policy.schema.json`: resolved single-policy contract.
- `schemas/output-policy-set.schema.json`: policy-bundle and profile contract.
- `schemas/command-result-envelope.schema.json`: caller-facing result envelope.
- `schemas/capture-manifest.schema.json`: immutable capture manifest.
- `schemas/observation.schema.json`: raw-free durable observation contract.
- `schemas/audit-event.schema.json`: audit event starter schema.
- `config/output-policies.example.yaml`: default and command-class policies.
- `examples/execution-envelope-fragment.yaml`: actionq/runner binding.
- `examples/command-result-envelope.json`: representative result.
- `examples/handoff-fragment.md`: portable handoff notation.
- `acceptance/SCENARIOS.md`: conformance cases.
- `IMPLEMENTATION_HANDOFF.md`: implementation packet.

## Frozen scope

Do not extend `outctl` as a compression, execution, orchestration, or
observability product. The commands below are retained as compatibility and
discovery controls only; they are not the recommended replacement stack.

The first sidecar commands are:

```bash
outctl import --spool-root .outctl \
  --stdout result.stdout --stderr result.stderr \
  --harness codex --session SESSION --tool-call TOOL_CALL \
  --command-sha256 COMMAND_SHA256 --duration-ms 417

outctl show --spool-root .outctl OBSERVATION_ID
outctl stdout --spool-root .outctl OBSERVATION_ID
outctl grep --spool-root .outctl OBSERVATION_ID OOMKilled
outctl diff --spool-root .outctl OBSERVATION_A OBSERVATION_B
outctl promote --spool-root .outctl OBSERVATION_ID --reason "supports diagnosis"
```

`outctl ingest` binds the same raw-free metadata to a capture produced by the
legacy adapter. Observation IDs are content-addressed; raw streams stay in
the verified capture store and are never copied into the observation JSON.
This functionality is frozen and may be removed later if the bounded
OTel/Langfuse/Phoenix spike makes it unnecessary.

## Development

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
```

Run the metadata-only mechanism and enablement gates with:

```bash
uv run outctl benchmark --spool-root /tmp/outctl-mechanism
uv run outctl enablement config/enablement-evidence.example.json
```

The CLI supports an opt-in direct-argv wrapper via `outctl run -- <argv>`,
bounded retrieval commands, and raw-free pilot-report validation. See
[`docs/WORKSTATION_PILOT_RUNBOOK.md`](docs/WORKSTATION_PILOT_RUNBOOK.md) for
the Codex/Claude appservice pilot and review procedure.

## Generalized scenario launcher

New controlled runs use `study-protocol/v3`, `scenario-suite/v2`, and a sealed
`arm-matrix/v1`. `outctl.harness.Launcher` plans every arm, scenario, and
replicate before execution, rotates matched start groups from the protocol
seed, and enforces the protocol's optional session, concurrency, and credit
limits. A null limit is intentional for exploratory runs; the estimate is
still emitted in the plan.

Scenario resolution is provider-based through
`outctl.scenarios.ScenarioHandler`. The first CI provider is
`ProcessFixtureProvider`; `KubernetesReplayProvider` keeps the existing
digest-bound replay available through the same interface. Historical v1/v2
study artifacts remain readable records and are not accepted as inputs to the
v3 analysis compiler.

## License status

No open-source license has been granted yet. The repository is public for
design and implementation collaboration, but ordinary copyright restrictions
apply until the owner chooses and adds a license.
