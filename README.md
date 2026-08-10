# Vuoro bounded command-output tooling starter

**Working component name:** `outctl`  
**Status:** Python v1 baseline with accepted hybrid migration direction
**Architecture accepted:** 2026-08-10

This package defines a small supplemental tool for the Vuoro ecosystem: capture complete command output outside the model context, return a bounded deterministic projection to the harness, and allow later slices to be retrieved without rerunning the command.

The design is deliberately narrow. `outctl` is not a scheduler, queue, workflow engine, shell, model router, knowledge store, or alternate Vuoro control plane.

## Recommended reading order

1. [`docs/architecture/README.md`](docs/architecture/README.md) — accepted target
   architecture and normative document index.
2. [`docs/MIGRATION_ROADMAP.md`](docs/MIGRATION_ROADMAP.md) — governing W0-W8
   migration sequence.
3. [`docs/DECISION_GATES.md`](docs/DECISION_GATES.md) — frozen direction,
   decisions requiring review, and stop conditions.
4. [`docs/DESIGN.md`](docs/DESIGN.md) and
   [`acceptance/SCENARIOS.md`](acceptance/SCENARIOS.md) — normative Python v1
   compatibility baseline.
5. [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and the accepted ADRs under
   [`docs/adr/`](docs/adr/).
6. [`docs/ENABLEMENT_PLAN.md`](docs/ENABLEMENT_PLAN.md) and
   [`docs/CONTRACT_INTEGRATION.md`](docs/CONTRACT_INTEGRATION.md) — existing
   pilot and ecosystem integration records, subordinate to the migration plan.

## Core decision

A command runs under the existing runner or harness. `outctl` observes its stdout/stderr, stores a recoverable capture, creates one or more bounded projections, and returns a result envelope. The command itself remains owned by the existing execution layer.

```text
sprintctl -> actionq -> runner/harness -> outctl capture/projection -> command
                    |                         |
                    |                         +-> host-local raw capture / optional replica
                    +-> auditctl receipts <---+

Vuoro: capability discovery, orchestration view, opaque references
kctl: curated policies and decisions, never raw command logs
```

## Package contents

- `docs/DESIGN.md`: full design.
- `schemas/output-policy.schema.json`: resolved single-policy contract.
- `schemas/output-policy-set.schema.json`: policy-bundle and profile contract.
- `schemas/command-result-envelope.schema.json`: caller-facing result envelope.
- `schemas/capture-manifest.schema.json`: immutable capture manifest.
- `schemas/audit-event.schema.json`: audit event starter schema.
- `config/output-policies.example.yaml`: default and command-class policies.
- `examples/execution-envelope-fragment.yaml`: actionq/runner binding.
- `examples/command-result-envelope.json`: representative result.
- `examples/handoff-fragment.md`: portable handoff notation.
- `acceptance/SCENARIOS.md`: conformance cases.
- `IMPLEMENTATION_HANDOFF.md`: implementation packet.

## Next implementation target

Execute W0 only: freeze the current Python behavior and contracts, run the full
quality/package gates, and establish fresh-process startup and syscall baselines.
Do not add a Cargo workspace or v2 runtime contracts until W0 reproduces the
current engine and its process semantics. See the
[migration roadmap](docs/MIGRATION_ROADMAP.md).

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

## License status

No open-source license has been granted yet. The repository is public for
design and implementation collaboration, but ordinary copyright restrictions
apply until the owner chooses and adds a license.
