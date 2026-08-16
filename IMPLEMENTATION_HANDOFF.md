# Historical implementation handoff: `outctl` Python Phase 1

> **Archived 2026-08-16.** No implementation work should follow this handoff.
> The repository is retained as a frozen discovery artifact after the product
> thesis was killed. See
> [`docs/DISCOVERY_KILL_2026-08-16.md`](docs/DISCOVERY_KILL_2026-08-16.md) for
> the replacement-first OTel/Langfuse hypothesis.

> **Status:** Baseline delivered. For new design and migration work, start at
> [`docs/architecture/README.md`](docs/architecture/README.md) and execute
> [`docs/MIGRATION_ROADMAP.md`](docs/MIGRATION_ROADMAP.md) wave by wave. This
> handoff remains the v1 compatibility record, not the active product plan.

## Objective

Build the smallest trustworthy local implementation of bounded, recoverable command output for the Vuoro ecosystem.

The delivered tool must capture command stdout/stderr outside model context, return a deterministic bounded projection, and retrieve omitted output by reference without rerunning the command.

## Authority constraints

Do not move or duplicate authority:

- sprintctl remains work/acceptance authority;
- actionq remains action lifecycle authority;
- the runner/harness remains command execution authority;
- auditctl remains evidence/finding authority;
- kctl remains curated decision/knowledge authority;
- Vuoro remains coordination/capability-discovery authority;
- `_artifacts/` remains semi-ephemeral and host-specific.

`outctl` owns only capture, projection, retrieval, verification, and retention mechanics.

## Required first slice

### Functional

1. Python 3.12 package and CLI.
2. Linux, non-PTY subprocess execution with direct argv.
3. Concurrent bounded-memory drainage of stdout and stderr.
4. Raw stream files plus chunk-level interleave event index.
5. Atomic capture manifest with SHA-256 hashes.
6. Generic projection:
   - full if small;
   - otherwise failure/warning anchors, head, and tail;
   - repeated-line and carriage-return progress collapse;
   - explicit gap markers;
   - byte, line, and estimated-token hard caps.
7. Model-facing redaction using exact values and configured patterns.
8. CLI commands:
   - `run`
   - `inspect`
   - `slice`
   - `tail`
   - `search`
   - `verify`
   - `recover`
   - `gc --dry-run`
   - `policy explain`
9. JSON result envelope matching the supplied schemas.
10. Feature modes: `bypass`, `shadow`, `enforce`.

### Non-functional

- no full-output buffering;
- no subprocess deadlock when stdout and stderr are both large;
- no implicit shell;
- no PTY emulation;
- no daemon/service requirement;
- no raw output in Git, kctl, sprintctl, or auditctl;
- local spool is 0700 and capture files are 0600;
- crash leaves recoverable explicit partial state;
- wrapper overhead is measured.

## Suggested PR sequence

### PR 1 — contracts, policy resolution, fixtures

- import schemas and example policies;
- typed models;
- canonical JSON and policy digest;
- fixture generators;
- direct/wrapped comparison harness;
- no command execution yet beyond tests.

Gate: schemas validate, digests are deterministic, acceptance fixtures are reviewed.

### PR 2 — capture engine and manifests

- subprocess process-group handling;
- concurrent pipe readers;
- local spool and atomic finalization;
- raw hashes and event index;
- command/capture status separation;
- recovery of partial captures.

Gate: large mixed-stream stress test, signals, timeout, disk/quota tests.

### PR 3 — projection and retrieval

- normalization/redaction;
- generic selector;
- budgets and markers;
- line indexes or correct linear retrieval for v1;
- inspect/slice/search/tail/verify;
- result envelope and human footer.

Gate: all Phase 1 acceptance scenarios pass.

### PR 4 — actionq adapter pilot

- output section in execution envelope;
- action/sprint/session bindings;
- one enforceable harness adapter;
- shadow and bypass modes;
- compact receipt emission.

Gate: real sprint run shows context savings and no-rerun retrieval.

## Implementation guidance

### Stream capture

Use `asyncio.create_subprocess_exec`, never `communicate()` for unbounded output. Drain both streams concurrently into files. Projection processing must not backpressure raw stream drainage.

### Event index

For each read chunk record:

```json
{"seq": 42, "stream": "stderr", "monotonic_ns": 123456789, "offset": 65536, "length": 4096}
```

This is enough to reconstruct observed chunk order while keeping exact stream bytes separate.

### Manifest finalization

Write into `partial/<capture>.tmp`, compute hashes, write and fsync the manifest, then rename atomically to `captures/<capture>`.

### Projection

Start deterministic. Do not add a model dependency. Preserve original ordering of selected spans and state every omitted range. Always include status, counts, reference, policy digest, and retrieval examples.

### Token estimate

Use a documented conservative estimator in v1, for example UTF-8 text bytes divided by a configurable ratio, and record estimator/version. The hard byte and line caps are the real safety bounds.

### Capture quota

Default 256 MiB per command. When reached, continue draining child pipes; mark truncation and last offsets. In required-capture mode, cancel according to policy.

### Secrets

Exact local raw is sensitive. Redact before model output. A remote/sanitized replica is a distinct artifact and hash. Test patterns that cross read-chunk boundaries.

## Do not build in this slice

- central service or database;
- remote command execution;
- PTY support;
- LLM summarization;
- automatic command retry;
- workflow/lifecycle logic;
- broad command-specific profile library;
- compressed chunk store unless measurements prove necessary;
- mandatory dependency on Vuoro/appservice availability.

## Required evidence in the implementation handoff

- repository and commit;
- test command and results;
- capture references for conformance fixtures;
- raw/projection byte and token estimates;
- hashes and verification output;
- source host and canonical path;
- whether captures are local-only or replicated;
- actionq/auditctl/kctl references when integration work begins;
- known deviations from the schemas/design;
- rollback flag and validation.

## Completion definition

Phase 1 is complete only when a fresh clone can run the acceptance suite and demonstrate:

1. a long command result is bounded;
2. the omitted middle is retrievable without rerun;
3. command exit/signal behavior matches direct execution;
4. raw output remains hash-verifiable;
5. secret and control-sequence fixtures are safe in projection;
6. disk/quota failure cannot deadlock the child;
7. bypass mode restores the ordinary runner path.
