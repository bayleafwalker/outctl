# Vuoro bounded command-output tooling starter

**Working component name:** `outctl`  
**Status:** implementation-ready repository scaffold  
**Date:** 2026-08-03

This package defines a small supplemental tool for the Vuoro ecosystem: capture complete command output outside the model context, return a bounded deterministic projection to the harness, and allow later slices to be retrieved without rerunning the command.

The design is deliberately narrow. `outctl` is not a scheduler, queue, workflow engine, shell, model router, knowledge store, or alternate Vuoro control plane.

## Recommended reading order

1. [`docs/DESIGN.md`](docs/DESIGN.md) — normative architecture and behavior.
2. [`docs/ADR-0001-HARNESS-BOUNDARY.md`](docs/ADR-0001-HARNESS-BOUNDARY.md) — why the wrapper belongs at the harness/runner boundary.
3. [`IMPLEMENTATION_HANDOFF.md`](IMPLEMENTATION_HANDOFF.md) — first delivery slices and stop conditions.
4. [`acceptance/SCENARIOS.md`](acceptance/SCENARIOS.md) — black-box acceptance suite.
5. [`config/output-policies.example.yaml`](config/output-policies.example.yaml) and [`schemas/`](schemas/) — starter contracts.
6. [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and [`docs/ROLLOUT.md`](docs/ROLLOUT.md).
7. [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) and
   [`docs/DEVBOX.md`](docs/DEVBOX.md) — autonomous pass sequence and devbox setup.
8. [`docs/ENABLEMENT_PLAN.md`](docs/ENABLEMENT_PLAN.md) — current ordered
   shadow, study, enforcement, integration, and rollback gates.

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

## First implementation target

Implement Linux, non-PTY, local capture first. Do not begin with a daemon, cluster service, LLM summarizer, or remote execution service. The first useful slice is a library plus CLI that:

- executes an argv vector without an implicit shell;
- drains stdout and stderr concurrently with bounded memory;
- writes raw streams and an interleave index atomically;
- returns a generic head/error/tail projection under a hard budget;
- provides `inspect`, `slice`, `search`, and `verify` without rerunning the command;
- records explicit truncation, capture failure, hashes, host, path, and policy digest.

That slice is enough to validate the premise against real Vuoro sessions before promoting it into every harness.

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
