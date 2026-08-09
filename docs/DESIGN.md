# Vuoro supplemental tooling design: bounded, recoverable command output

**Working name:** `outctl`  
**Status:** Proposed, implementation-ready starter  
**Date:** 2026-08-03  
**Intended consumers:** Vuoro, actionq/dispatcher, runner implementations, Claude Code/Codex/OpenCode adapters, sprintctl, auditctl, kctl, AgentOps project sessions

---

## 1. Executive decision

Add a thin command-result capture and projection component at the **runner/harness command boundary**.

For every wrapped command, the component:

1. executes or observes the command without changing its ordinary process semantics;
2. drains stdout and stderr continuously into a bounded-memory capture pipeline;
3. preserves complete raw output when permitted by the capture policy and quota;
4. returns a deterministic, budget-bounded projection to the model-facing harness;
5. exposes opaque references for later range, tail, and search retrieval without rerunning the command;
6. emits compact receipts suitable for actionq and auditctl;
7. keeps raw output outside kctl, sprintctl, Git, and ordinary conversation context.

The component is supplemental infrastructure. It is not authoritative for work state, action lifecycle, knowledge, audit conclusions, deployment state, or model routing.

The working CLI/repository name in this document is **`outctl`**. The name can change without changing the design.

---

## 2. Motivation and measured evidence

A long-lived Opus 5 session reported:

- total occupied context: **565.1k / 1m tokens**;
- message content: **542.6k tokens**;
- Bash results: **178.8k tokens**;
- estimated avoidable Bash output from elementary filtering: **89.4k tokens**.

Bash output therefore represented:

- 17.88% of the entire one-million-token window;
- 32.95% of all message tokens;
- 31.64% of occupied context.

This is not merely a prompt-writing problem. Shell output becomes a major context author, even when most of it consists of repeated progress, passing tests, recursive listings, generated text, unchanged context lines, or logs that are useful only after a failure is identified.

Manual `head`, `tail`, and `grep` mitigate the immediate symptom but are structurally weak:

- they depend on model discipline;
- they discard information before a stable evidence object exists;
- they often force a rerun when the omitted section becomes relevant;
- reruns may be expensive, stateful, or non-reproducible;
- they cannot provide uniform metrics across harnesses;
- they do not create a portable reference for handoff or audit.

The design goal is therefore **lossy model exposure backed by recoverable evidence**, not indiscriminate truncation.

---

## 3. Goals

### 3.1 Primary goals

1. **Bound model-visible output.** One command result must not consume an unbounded fraction of a session context.
2. **Avoid information-destroying truncation.** Preserve raw output within explicit policy and quota limits.
3. **Retrieve without rerun.** Allow deterministic range, tail, stream, and search access to an existing capture.
4. **Preserve command semantics.** Exit status, signal handling, cancellation, cwd, argv, environment policy, and stream draining must remain correct.
5. **Make loss explicit.** Every projection states whether data was omitted, normalized, deduplicated, or redacted.
6. **Create portable evidence references.** A handoff can identify the source host/path, hashes, replicas, policy, and durable audit references.
7. **Use one contract across harnesses.** Claude Code, Codex, OpenCode, a native Vuoro runtime, and actionq runners should see the same result model.
8. **Measure value.** Record captured versus exposed bytes/lines/estimated tokens and follow-up retrievals.
9. **Retain break-glass operation.** Local execution and local retrieval must work without the served Vuoro stack.
10. **Remain replaceable.** The feature should be bypassable without changing sprint, action, or audit authorities.

### 3.2 Secondary goals

- deterministic command-class profiles for tests, builds, diffs, logs, listings, and structured output;
- optional host-local and remote replica backends;
- optional on-demand MCP or native retrieval tools;
- GitOps-managed policy distribution for served environments;
- structured receipts that can be inspected by humans and agents.

---

## 4. Non-goals

`outctl` must not become:

- a shell or general command language;
- a command scheduler or workflow engine;
- a replacement for actionq leases, retries, cancellation, or terminal outcomes;
- a replacement for sprintctl work definitions or acceptance criteria;
- a replacement for auditctl findings and evidence judgments;
- a replacement for kctl curated knowledge and decisions;
- a model router or prompt orchestration framework;
- a generic log aggregation platform;
- a second Git artifact authority;
- a database for arbitrary large blobs;
- an LLM summarization service in the core path;
- a mandatory cluster dependency for local interactive work;
- an excuse to return less evidence than a failure needs.

A daemon, central service, PTY recorder, remote executor, and semantic/LLM summarizer are explicitly outside the first implementation slice.

---

## 5. Authority and ownership boundaries

The central architectural rule is that command-output handling owns **capture mechanics and projections only**.

| Component | Authoritative responsibility | Relationship to `outctl` |
|---|---|---|
| **Vuoro** | User-facing coordination, capability discovery, cross-component view, opaque resource references | Advertises output-capture capability and resolves references; does not own command lifecycle or raw logs |
| **sprintctl** | Work state, readiness, dependencies, acceptance criteria | May require an output policy or evidence receipt; stores neither raw output nor projection bodies |
| **actionq** | Claims, leases, retries, cancellation, action lifecycle, terminal outcome | Passes output policy in the execution envelope and binds capture IDs to action IDs |
| **Runner / harness adapter** | Actually invokes commands and harnesses, observes cancellation, returns execution result | Integrates the capture library or wraps the command tool; remains execution owner |
| **`outctl`** | Stream capture, raw artifact layout, deterministic projection, retrieval, verification, retention mechanics | Produces captures, projections, references, and compact receipts |
| **auditctl** | Immutable observations, receipts, findings, and evidence trail | Records hashes, policy digest, capture status, projection exposure, replica state, and verification results |
| **kctl** | Curated knowledge, decisions, active policy intent, promotion | Stores policy decisions and durable interpretation; never receives bulk raw command output |
| **AgentOps / project folder** | Project discovery, repo relationships, session setup, authored guidance | Distributes config and skills; points to captures in handoffs but does not make `_artifacts/` authoritative |
| **Git** | Maintained specifications, schemas, policies, code, runbooks | Stores the design and policy definitions; never stores routine command output |
| **`_artifacts/`** | Semi-ephemeral host-local exports | May contain captures, but portability requires explicit host/path/hash/replica metadata |

### 5.1 Consequence

A capture reference is evidence about an execution. It is not proof that a sprint is done, that an action succeeded semantically, or that an audit finding passed. Those conclusions remain with their existing owners.

---

## 6. Placement in the execution path

### 6.1 Normative placement

```text
execution envelope
      |
      v
runner / harness adapter  ---- cancellation / timeout / environment ----+
      |                                                                |
      v                                                                |
outctl capture boundary                                                   |
      |                                                                |
      +---- spawn argv or observe subprocess --------------------------+
      |
      +---- stdout.raw
      +---- stderr.raw
      +---- interleave event index
      +---- capture manifest
      +---- deterministic projection
      +---- result envelope
```

The wrapper belongs **inside the runner or command-tool adapter**, not in the planner and not as a prompt convention. This is the lowest layer that can both preserve subprocess correctness and control what enters model context.

### 6.2 Integration levels

Three integration levels are supported:

1. **Native library integration — preferred.** The runner calls the capture API directly around subprocess execution.
2. **CLI wrapper integration — acceptable starter.** The runner invokes `outctl run -- <argv>` and consumes JSON/JSONL output.
3. **Policy-only invocation — temporary compatibility.** Skills instruct an agent to prefix commands with `outctl run`. This is useful for pilots but is not enforcement and must not be presented as complete integration.

Where a harness can withhold its ordinary shell tool and expose only a wrapped command tool, that is the strongest stock-harness integration. Where it cannot, the design remains opt-in until a reliable adapter exists.

### 6.3 Retrieval tool placement

Retrieval may be exposed as an on-demand harness tool or MCP tool:

- `command_output.inspect`
- `command_output.slice`
- `command_output.search`
- `command_output.tail`
- `command_output.verify`

Do not expose a second generic command executor through MCP when the harness already owns command execution. The retrieval surface is supplemental; the runner remains the only execution path.

---

## 7. Conceptual model

### 7.1 Invocation

The command request after policy resolution, containing:

- argv vector;
- explicit shell mode, normally false;
- cwd and workspace identity;
- filtered environment description;
- timeout and cancellation binding;
- actor, harness, host, action, sprint, and correlation identifiers;
- output policy name and content digest.

### 7.2 Capture

An immutable collection of observed command-result bytes and metadata:

- raw stdout bytes;
- raw stderr bytes;
- chunk-level interleave index;
- command status;
- capture status;
- hashes and limits;
- source host and local locator;
- optional replicas.

A capture may be complete, incomplete, quota-truncated, unavailable, or expired. “Capture exists” never silently implies “complete raw output exists.”

### 7.3 Projection

A deterministic, model-facing view derived from a capture under a named policy. A projection may:

- normalize ANSI/control sequences;
- decode bytes for display;
- collapse progress updates;
- collapse repeated lines;
- select head, tail, error, warning, changed-hunk, or structured spans;
- insert explicit gap markers;
- redact known sensitive values;
- enforce byte, line, and estimated-token budgets.

A projection is not the raw evidence object. It has its own ID and digest.

### 7.4 Retrieval

A deterministic read against a capture reference, such as:

- stream byte range;
- line range;
- final N lines;
- regular-expression search with context;
- event sequence range;
- structured selector, when a parser profile is applicable.

Retrieval creates another bounded projection. It never reruns the command.

### 7.5 Receipt

A compact, durable record suitable for actionq/auditctl:

- capture reference and manifest digest;
- policy digest;
- command/capture status;
- raw and exposed sizes;
- redaction and truncation flags;
- source host/path classification;
- replica status;
- timestamps and correlation IDs.

### 7.6 Replica

A verified copy of some capture material. Replica classes are explicit:

- `raw-exact`: exact raw bytes and manifest;
- `raw-sanitized`: redacted bytes, not equivalent to exact raw;
- `manifest-only`: metadata and hashes only;
- `projection-only`: model-facing material only.

A handoff must not call a local capture portable unless a retrievable replica exists on the receiving side.

---

## 8. Capture lifecycle and states

### 8.1 State model

```text
ALLOCATED
    |
    v
RUNNING ------------------------------+
    |                                 |
    | command exits                   | wrapper/process crash
    v                                 v
FINALIZING                         PARTIAL
    |                                 |
    +--> COMPLETE                     +--> RECOVERED_INCOMPLETE
    +--> CAPTURE_TRUNCATED             +--> ABANDONED
    +--> CAPTURE_DEGRADED
    +--> CAPTURE_FAILED

COMPLETE / TRUNCATED / DEGRADED / RECOVERED_INCOMPLETE
    |
    +--> REPLICATED (zero or more replicas)
    +--> EXPIRED (raw removed, manifest tombstone retained as policy allows)
```

### 8.2 Command status versus capture status

These are separate dimensions.

Examples:

- command exit `0`, capture `COMPLETE`;
- command exit `1`, capture `COMPLETE`;
- command exit `0`, capture `CAPTURE_TRUNCATED` due quota;
- command killed by signal, capture `COMPLETE` through final observed byte;
- command still succeeded, local disk failed, capture `CAPTURE_FAILED`;
- command never started because wrapper setup failed.

The result envelope must never collapse these into one ambiguous “success” field.

### 8.3 Fail-open and fail-closed

Policy selects behavior:

- **Interactive default:** fail open. Preserve command execution, emit a prominent capture warning, and return whatever bounded live projection remains available.
- **Audited action requiring evidence:** fail closed. If capture cannot be established or becomes unusable, cancel the child process group and return a distinct infrastructure failure to the runner.

The execution envelope must state whether capture is required. The runner, not `outctl`, decides the action’s terminal lifecycle result.

---

## 9. On-disk artifact design

### 9.1 Local spool

Default root:

```text
${XDG_STATE_HOME:-~/.local/state}/outctl/
```

A project or AgentOps environment may redirect this to a host-local `_artifacts/outctl/` path. Such a path remains semi-ephemeral and must be described as local evidence, not as a durable authority.

Suggested layout:

```text
outctl/
  captures/
    01K1ABC.../
      manifest.json
      stdout.raw
      stderr.raw
      events.ndjson
      indexes/
        stdout.lines
        stderr.lines
      projections/
        01K1PROJ....json
        01K1PROJ....txt
      replicas.json
  partial/
    01K1ABC....tmp/
  index.sqlite3
  locks/
```

### 9.2 Atomicity

1. Allocate a ULID capture ID.
2. Create a mode-0700 temporary directory under `partial/`.
3. Open raw streams with mode 0600.
4. Stream bytes and event metadata.
5. Flush and close streams.
6. Compute final hashes and write `manifest.json.tmp`.
7. `fsync` files and directory where supported.
8. Atomically rename the partial directory into `captures/<id>/`.
9. Update the rebuildable SQLite index.

The manifest and files are authoritative for the local capture. SQLite is only an index/cache and must be rebuildable.

### 9.3 Raw stream preservation

- stdout and stderr remain separate raw byte streams.
- The wrapper also records an event index containing sequence, stream, monotonic timestamp, offset, and length for every captured chunk.
- The event index reconstructs the wrapper’s observed chunk order. It does not claim byte-perfect real-world simultaneity between OS pipes.
- Raw bytes are never decoded or normalized in place.

### 9.4 Memory and I/O constraints

- Read stdout and stderr concurrently.
- Use bounded queues and streaming writes; never accumulate complete output in memory.
- Recommended read chunk: 64 KiB.
- Recommended projection line limit: 1 MiB per logical line. Longer lines remain in raw output but are clipped in projections with an explicit marker.
- Default complete-capture quota: 256 MiB per command, configurable by policy.
- Default workspace spool quota: 10 GiB, configurable.
- Quota overflow results in explicit `CAPTURE_TRUNCATED`; it must not silently discard bytes.

A future implementation may use independently compressed chunks and sparse indexes. The first implementation should prefer correctness and inspectability over premature storage cleverness.

### 9.5 Encoding and binary data

- Raw capture is encoding-agnostic.
- Projection attempts UTF-8 first and uses replacement characters only in the projection.
- The chosen decoder and replacement count are recorded.
- If output appears binary beyond a policy threshold, the default projection returns metadata, safe printable excerpts, and the capture reference rather than injecting arbitrary bytes into the model context.

---

## 10. Capture references and portability

### 10.1 Opaque reference

Recommended reference syntax:

```text
outctl://capture/<capture-ulid>/manifest/sha256/<manifest-digest>
```

The reference identifies a capture and pins the manifest digest. It intentionally does not embed a filesystem path or host. Resolution is performed through local metadata or an optional registry.

### 10.2 Source locator

The envelope separately records:

- `host_id`;
- canonical local path;
- workspace/project ID;
- repository and commit when known;
- path classification: local spool, `_artifacts/`, or replicated object;
- capture and manifest hashes.

### 10.3 Handoff rule

Every handoff reference must state one of:

- **portable:** verified replica available at a durable locator;
- **receiving-host available:** replica verified on the named target host;
- **local-only:** source host/path required; no portability claim;
- **expired:** manifest receipt remains, raw material unavailable.

A bare path is insufficient. A bare capture ID is also insufficient when no registry is available.

### 10.4 Replica registration

Replication is content-addressed and idempotent. A replica record includes:

- replica class;
- backend and locator;
- digest and byte count;
- encryption/sanitization status;
- verification timestamp;
- retention class;
- access scope.

Exact raw and sanitized raw are never represented as equivalent replicas.

---

## 11. Projection policy

### 11.1 Hard budget

A projection is constrained by all configured limits:

- maximum output bytes;
- maximum output lines;
- maximum estimated tokens.

The first reached limit wins. Token counts are estimates unless a harness supplies an exact tokenizer. Every estimate records the estimator name and version; false precision is worse than a useful approximation.

Recommended initial defaults:

| Context | Max estimated tokens | Max bytes | Max lines |
|---|---:|---:|---:|
| Ordinary interactive command | 6,000 | 32 KiB | 600 |
| Failure-oriented test/build command | 8,000 | 48 KiB | 900 |
| Compact metadata command | 4,000, normally full | 24 KiB | 500 |
| Explicit retrieval slice | 6,000 | 32 KiB | 600 |
| Hard per-result ceiling without explicit override | 12,000 | 64 KiB | 1,200 |

The caller may lower the budget based on remaining context. `outctl` enforces a supplied budget; it does not need to know the model’s entire conversation.

### 11.2 Projection modes

Normative v1 modes:

- `auto`: classify and select a deterministic profile;
- `full-if-small`: return full normalized text if it fits, otherwise use generic bounded mode;
- `head-tail`: preserve configured head and tail spans;
- `failure`: prioritize failure anchors and surrounding context, plus summary and tail;
- `search`: return matches and context for explicit patterns;
- `line-range`: return requested stream line ranges;
- `structured`: return selected keys/paths or a structural outline for valid JSON-like output;
- `metadata-only`: no text body, only counts, status, hashes, and references.

Optional later modes:

- changed-hunk-aware diff selection;
- compiler diagnostic grouping;
- test-framework adapters;
- chunked follow/progress views.

### 11.3 Generic deterministic selection algorithm

For oversized text output:

1. Build a normalized display view while preserving raw bytes separately.
2. Detect control sequences, carriage-return progress updates, repetition, encoding anomalies, and candidate failure/warning anchors.
3. Reserve budget for the result header, command status, capture reference, omission metrics, and final tail.
4. Create candidate spans:
   - failure/error/traceback spans with context;
   - warning spans;
   - configured explicit selector spans;
   - head span;
   - tail span;
   - phase-boundary or summary spans when recognized deterministically.
5. Rank spans by policy priority, but merge and present selected spans in original output order.
6. Collapse exact or normalized consecutive repetitions and carriage-return progress updates.
7. Insert gap markers containing omitted line/byte ranges when known.
8. Enforce all hard budgets after markers and redaction.
9. Emit projection metadata and digest.

Example marker:

```text
[... omitted stdout lines 418-9,882; retrieve with:
 outctl slice <capture-ref> --stream stdout --lines 418:9882 ...]
```

### 11.4 Required visible footer/header

Every lossy model-facing result must expose:

- command exit status or signal;
- capture status;
- raw stdout/stderr byte and line counts when known;
- exposed byte/line/estimated-token counts;
- `truncated`, `normalized`, `deduplicated`, and `redacted` flags;
- capture reference;
- policy name and digest prefix;
- one or more concrete retrieval examples.

Loss must never be inferred from a mysteriously short output.

### 11.5 Repetition and progress normalization

Projection-only normalization may:

- collapse consecutive identical lines after a configurable threshold;
- normalize timestamps or counters only for repetition comparison, not in displayed representative lines;
- retain the first and final progress state for carriage-return updates;
- retain any progress line containing a failure/warning anchor;
- represent a collapse as `[line repeated N times; raw lines A-B]`.

Raw capture remains unchanged.

### 11.6 Command profiles

Explicit profile selection from the execution envelope takes precedence. Argv-based classification is a fallback and must be conservative.

| Profile | Initial behavior |
|---|---|
| `generic` | Full if small; otherwise errors/warnings + head + tail |
| `tests` | Framework summary, failures, tracebacks, warnings, tail; passing-case chatter heavily bounded |
| `build` | Phase boundaries, compiler/errors, warnings, final summary, tail |
| `git-status` | Normally full; preserve porcelain semantics when requested |
| `git-diff` | Diff stat, changed file list, bounded complete hunks; explicit omitted-hunk index |
| `k8s-get` | Prefer caller-requested columns/JSON paths; otherwise full if small |
| `k8s-logs` | Severity/error anchors, repetition collapse, time-ordered tail |
| `listing` | Counts, depth summary, bounded representative entries, tail |
| `structured` | Validity, top-level shape, selected paths, bounded pretty output |
| `binary` | Metadata and printable excerpts only |

Profiles may supply selectors, but they cannot change command execution or claim domain success.

### 11.7 No LLM summarizer in the core path

The core projector must be deterministic and locally reproducible. A later consumer may ask a model to summarize a referenced capture, but that produces a separate derived artifact with its own provenance. It must never replace raw capture or the deterministic projection.

---

## 12. Redaction and sensitive output

### 12.1 Three distinct surfaces

1. **Local exact raw:** highest fidelity and highest sensitivity.
2. **Replicated material:** may need sanitization before leaving the host.
3. **Model-facing projection:** must apply configured redaction before context exposure.

Policies control each surface separately.

### 12.2 Recommended default

- Exact raw captured locally with directory 0700 and files 0600.
- Model projection redacted.
- Remote replication sanitized by default unless the backend and authorization explicitly permit exact raw.
- Command metadata displays a redacted argv/environment representation while preserving a protected exact invocation receipt only where required.
- Raw local retention is short and quota-managed.

### 12.3 Redaction sources

The redactor should support:

- exact secret values supplied by the harness from its secret broker/environment allowlist;
- configurable regular expressions for tokens, credentials, private keys, connection strings, and common authorization headers;
- path and identity substitutions where policy requires;
- structured-field redaction for JSON/YAML profiles.

Streaming redaction must handle patterns crossing chunk boundaries by retaining an overlap window. Redaction counts and rule IDs are recorded; secret values are never recorded in the receipt.

### 12.4 Limits

No regex-based redactor can guarantee discovery of all secrets. The design therefore combines:

- least-privilege environment injection;
- command argument hygiene;
- local file permissions;
- short retention;
- explicit replica policy;
- redaction before model exposure;
- audit visibility when redaction was or was not applied.

“Captured locally” is not equivalent to “safe to replicate.”

---

## 13. Command execution semantics

### 13.1 Invocation

- Default to direct argv execution; no implicit shell.
- Shell mode must be explicit and recorded.
- Preserve cwd and the runner-provided environment.
- Do not reinterpret quoting or globbing.
- Record a safe display form separately from the actual argv.

### 13.2 Stream draining

- Drain stdout and stderr concurrently to avoid deadlock.
- Capture bytes even when the projector has exhausted its model-facing budget.
- Keep projection queues bounded; projection backpressure must not block raw stream draining.

### 13.3 Signals and cancellation

- Spawn the child in a controllable process group where supported.
- Forward interrupt/termination according to runner policy.
- Record requested cancellation, signals sent, grace period, escalation, and final status.
- Do not convert a cancelled command into an ordinary nonzero exit without metadata.

### 13.4 Exit behavior

For CLI compatibility:

- when the child starts, `outctl run` normally exits with the child’s exit status;
- when the command cannot start, use a reserved wrapper failure status and emit a result envelope;
- when capture is required and capture setup fails, do not start the child;
- when required capture fails mid-command, terminate according to policy and report both command and capture states.

The structured result envelope is authoritative because one POSIX exit code cannot represent both command and capture dimensions.

### 13.5 TTY and interactive programs

PTY capture is excluded from v1. Commands that require an interactive terminal should bypass the wrapper or use a future PTY-specific mode. Pretending a pipe is a terminal changes behavior and violates the “preserve semantics” requirement.

---

## 14. Result contracts

The starter schemas live under `schemas/`.

### 14.1 Execution-envelope fragment

The actionq/runner execution envelope adds an output section:

```yaml
output:
  policyRef:
    name: interactive-default-v1
    digest: sha256:...
  profile: auto
  captureRequired: false
  backend: local
  modelBudget:
    maxEstimatedTokens: 6000
    maxBytes: 32768
    maxLines: 600
  bindings:
    sprintId: sprintctl:...
    actionId: actionq:...
    auditScope: auditctl:...
```

The policy digest is pinned. A mutable policy name alone is insufficient for reproducibility.

### 14.2 Command-result envelope

The runner receives a structured envelope containing:

- schema and capture references;
- invocation metadata and bindings;
- command outcome;
- capture outcome and hashes;
- one inline or referenced model projection;
- retrieval capabilities;
- replica state;
- metrics.

The inline projection may be omitted in `metadata-only` mode, but the result header remains available.

### 14.3 Capture manifest

The immutable manifest pins:

- raw stream hashes and sizes;
- interleave event-index hash;
- command/capture status;
- policy digest;
- source identity;
- capture limits and truncation points;
- projection records;
- manifest schema version.

Mutable replica and retention data should live in a separate signed/hashed record so adding a replica does not change the original capture digest.

### 14.4 Schema evolution

- Use explicit schema versions.
- Readers must reject unknown required semantics but tolerate unknown optional fields.
- Never redefine an existing field’s meaning.
- Store policy and schema digests in receipts.
- Support one-version-back reading during migrations.

---

## 15. CLI and library surface

### 15.1 CLI

```text
outctl run [capture/policy options] -- <argv...>
outctl inspect <capture-ref> [--json]
outctl slice <capture-ref> --stream stdout|stderr|merged --lines A:B
outctl slice <capture-ref> --stream stdout|stderr --bytes A:B
outctl tail <capture-ref> --stream stdout|stderr|merged --lines N
outctl search <capture-ref> --regex PATTERN [--before N] [--after N]
outctl verify <capture-ref> [--replica LOCATOR]
outctl replicate <capture-ref> --backend NAME [--class raw-exact|raw-sanitized|manifest-only|projection-only]
outctl policy explain --policy-ref NAME[@DIGEST] --argv ...
outctl recover [--spool PATH]
outctl gc [--dry-run] [--workspace ID]
```

### 15.2 Output formats

- Human text: bounded projection plus explicit receipt footer.
- JSON: complete result envelope.
- JSONL: lifecycle events for native adapters.

Machine integrations must consume JSON or library models, not scrape human text.

### 15.3 Python library starter

Recommended first implementation language: **Python 3.12**, matching the existing dispatcher/adapter environment and minimizing integration cost. The public library should be async-first and avoid shell semantics.

Conceptual API:

```python
result = await outctl.capture.run(
    CommandRequest(
        argv=["pytest", "-q"],
        cwd=workspace,
        output_policy=resolved_policy,
        bindings=ExecutionBindings(...),
    ),
    cancellation=runner_cancellation,
)
```

The library returns a typed `CommandResultEnvelope`. The CLI is a thin adapter over the same API.

A later rewrite or high-performance worker remains possible because the JSON schemas and artifact format, not Python classes, are the stable ABI.

### 15.4 Minimal implementation dependencies

Prefer a small dependency set:

- Python standard-library subprocess/asyncio, hashing, pathlib, sqlite3, json;
- a schema/model library such as Pydantic v2;
- YAML parsing for policies;
- optional zstandard only after the uncompressed format is proven;
- no model SDK in the core package.

---

## 16. Integration with Vuoro and related components

### 16.1 Vuoro

Vuoro should expose `outctl` as a discovered capability:

```json
{
  "capability": "command-output.capture.v1",
  "modes": ["local", "hybrid"],
  "retrieval": ["inspect", "slice", "search", "tail", "verify"],
  "policy_digests": ["sha256:..."]
}
```

Vuoro may resolve opaque capture references and show replica/availability status. It must not become the raw blob owner in v1 and must not infer action success from command exit alone.

### 16.2 sprintctl

A sprint item may state:

- required output policy/profile;
- whether exact raw evidence is required;
- required retention/replication class;
- acceptance checks that consume a capture reference.

sprintctl stores the requirement and resulting compact reference, not bulk output.

### 16.3 actionq

Actionq adds output policy to the execution envelope and binds captures to action attempts. Each retry gets a distinct capture ID. The action attempt record can point to:

- primary command capture;
- verification command captures;
- terminal candidate receipt.

Actionq continues to own retries and terminal outcomes. `outctl` must not retry commands.

### 16.4 Runner and harness adapters

Adapters must:

1. resolve/pin the output policy;
2. pass action/sprint/session/host bindings;
3. use the library or CLI wrapper;
4. return only the bounded projection to model context;
5. expose retrieval tools by capture reference;
6. pass compact receipts to actionq/auditctl;
7. maintain a bypass feature flag.

For stock harnesses that cannot intercept their native shell tool, initial integration may rely on a wrapped command tool and explicit deny/allow policy. Compliance should be tested rather than assumed.

### 16.5 auditctl

Recommended event types:

- `command.capture.completed`
- `command.capture.degraded`
- `command.capture.truncated`
- `command.projection.exposed`
- `command.output.retrieved`
- `command.capture.verified`
- `command.capture.replicated`
- `command.capture.expired`

Do not flood the durable ledger with every interactive local command by default. Recommended promotion rules:

- local interactive captures remain local receipts;
- action-bound captures publish completion receipts;
- evidence used for acceptance or findings is promoted explicitly;
- retrieval events may be aggregated per action/session unless compliance requires each access.

Auditctl records observations and verification. It does not store raw byte streams.

### 16.6 kctl

kctl stores curated decisions such as:

- active default output policy;
- approved redaction rule set;
- retention/replication decision;
- accepted schema version;
- known limitations or exceptions.

Policy files remain maintained in Git and are referenced by digest. kctl captures the decision and rationale, not a duplicate policy blob and never routine command output.

### 16.7 AgentOps project folders and handoffs

Project guidance should explain:

- where `outctl` is enabled;
- the active policy reference;
- how to retrieve a capture;
- what host-local paths mean;
- how to replicate evidence before cross-host handoff.

A handoff must include source host/path, capture reference, hashes, replica status, retention, and durable audit/kctl references. `_artifacts/` is an export location, not authority.

### 16.8 appservice and served mode

The first implementation is local. A later served capability may provide:

- metadata registry;
- reference resolution;
- authorization;
- replica registration;
- object-store-backed retrieval.

Large raw streams should go to an object/artifact backend, not CNPG rows. The database may store metadata, bindings, and replica records. Deployment configuration and policy bundles can be reconciled through the existing GitOps/appservice path.

### 16.9 Local, hybrid, and remote-only behavior

- **Local:** capture and retrieve entirely from the host spool; break-glass default.
- **Hybrid:** capture locally, register metadata, and replicate according to policy; local resolution first.
- **Remote-only:** permitted only after a service/backend exists; fail before command start when required remote capture cannot be established.

Execution location and capture backend are separate concerns. A remote registry must not silently turn `outctl` into a remote command executor.

---

## 17. Observability and economics

### 17.1 Per-command metrics

Record:

- stdout/stderr/raw total bytes and lines;
- capture duration and finalize duration;
- exposed bytes/lines;
- estimated input tokens before projection and after projection;
- estimated tokens avoided;
- projection mode/profile;
- repetition collapse count;
- redaction count by rule ID;
- capture and spool quota state;
- retrieval count and total retrieved bytes/tokens;
- replica class and latency;
- capture overhead versus command duration where measurable.

### 17.2 Session/action aggregates

Useful aggregates:

- total command-output context exposed;
- raw-to-exposed ratio;
- largest offending commands;
- percentage of captures later retrieved;
- reruns plausibly avoided, when the caller marks a retrieval as replacing a rerun;
- failure diagnostic retrieval rate;
- capture failures and quota truncations.

### 17.3 Initial success targets

For the pilot corpus:

- at least 50% reduction in model-visible tokens for oversized command outputs;
- 100% explicit marking of any lossy projection;
- 100% retrieval of retained ranges without rerunning the command;
- no subprocess deadlocks in stress tests;
- no command-status changes attributable to projection logic;
- less than 5% median runtime overhead when the direct median is at least
  1,000 ms, or at most 100 ms median absolute overhead below that boundary,
  using at least five alternating paired repetitions and excluding optional
  replication;
- no unbounded memory growth with multi-gigabyte synthetic output;
- no exact secret fixture exposed in model projection or sanitized replica tests.

The measured 178.8k-token Bash baseline should be retained as one comparison scenario.

---

## 18. Failure handling and recovery

### 18.1 Disk full or quota reached

- Mark capture truncated/degraded immediately.
- Continue draining child pipes to avoid deadlock, discarding only according to explicit quota policy.
- Preserve a bounded emergency projection in memory when possible.
- If capture is required, cancel the child and report infrastructure failure.
- Emit quota and last-captured offsets.

### 18.2 Wrapper crash

`outctl recover` scans `partial/` and:

- validates present files;
- computes hashes for observed bytes;
- writes a `RECOVERED_INCOMPLETE` manifest where useful;
- records the absence of a trustworthy final command status;
- removes irrecoverable empty remnants after retention policy permits.

### 18.3 Hash mismatch

- Mark the local or replica material unverified/tampered.
- Never silently regenerate a digest.
- Keep the expected manifest digest and observed digest.
- Audit promotion requires an explicit verification result.

### 18.4 Missing local evidence

When a reference resolves only to an expired or unavailable local capture:

- return metadata and replica state;
- do not rerun automatically;
- do not imply the handoff is portable;
- let the runner/planner decide whether a new execution is necessary.

### 18.5 Projection failure

Projection failure must not destroy raw capture. Fall back to a generic bounded head/tail projection and mark `projection_degraded`. If even that fails, return metadata-only with retrieval reference.

---

## 19. Security model summary

Detailed threats are in `THREAT-MODEL.md`. The minimum controls are:

- no implicit shell;
- workspace-scoped authorization and path resolution;
- mode-0700 spool and mode-0600 files;
- safe symlink handling and atomic creation;
- separate exact and redacted representations;
- redaction before model exposure;
- command/env display redaction;
- bounded disk and memory;
- ANSI/control-sequence neutralization in projections;
- manifest and stream hashes;
- policy digest pinning;
- explicit replica classes;
- short raw retention;
- no routine raw logs in Git, kctl, sprintctl, or auditctl;
- no automatic execution during retrieval.

Command output is untrusted input. A log line that says “ignore prior instructions” is still a log line, not a control instruction. Adapters should preserve tool-result boundaries and provenance labels.

---

## 20. Repository design for implementation

Recommended repository layout:

```text
outctl/
  README.md
  pyproject.toml
  src/outctl/
    __init__.py
    cli.py
    models.py
    policy.py
    capture/
      runner.py
      streams.py
      manifest.py
      storage.py
      recovery.py
    projection/
      generic.py
      selectors.py
      normalize.py
      redact.py
      profiles/
        tests.py
        build.py
        git.py
        kubernetes.py
        structured.py
    retrieval/
      inspect.py
      slice.py
      search.py
      verify.py
    integration/
      actionq.py
      auditctl.py
      vuoro.py
  schemas/
  policies/
  tests/
    unit/
    integration/
    conformance/
    fixtures/
  adapters/
    opencode/
    codex/
    claude-code/
  deploy/
    optional-service/
  docs/
```

Keep adapter-specific code outside the capture core. The core should be usable from a local runner with no Vuoro service connection.

---

## 21. Delivery phases

### Phase 0 — measurement and contracts

- Commit schemas, policy examples, ADR, and fixtures.
- Add instrumentation around existing harness output where possible without changing exposure.
- Reproduce the 178.8k-token class of session data with synthetic and real command fixtures.

Exit condition: baseline reports can identify raw/exposed output by command and harness.

### Phase 1 — local generic capture

- Linux, non-PTY subprocess capture.
- Raw stdout/stderr and interleave index.
- Atomic manifest.
- Generic full-if-small/error/head/tail projection.
- `run`, `inspect`, `slice`, `search`, `tail`, `verify`, `recover`, and dry-run `gc`.
- Hard byte/line/token-estimate budgets.
- Local exact raw plus model projection redaction.

Exit condition: all P0/P1 acceptance scenarios pass; no actionq dependency.

### Phase 2 — actionq and one harness adapter

- Add execution-envelope binding.
- Integrate one runner/harness end to end.
- Publish compact action receipts.
- Add bypass flag and shadow/compare mode.

Recommended pilot: the adapter where the ordinary command tool can be reliably replaced or intercepted. Do not choose based on brand preference; choose based on enforcement and observability.

Exit condition: a real implementation sprint completes with reduced context and successful no-rerun retrieval.

### Phase 3 — profiles and audit integration

- Test/build/git/k8s/structured profiles.
- auditctl receipt promotion and verification.
- kctl policy decision record.
- AgentOps project guidance and handoff templates.

Exit condition: conformance results are comparable across at least two harnesses.

### Phase 4 — hybrid replicas and Vuoro discovery

- Optional metadata registry and object/artifact backend.
- Portable opaque reference resolution.
- cross-host replica verification;
- GitOps policy distribution;
- Vuoro capability/resource presentation.

Exit condition: workstation-to-devbox handoff retrieves a verified replica without a shared local path.

### Phase 5 — optional advanced features

Only after measured need:

- PTY capture;
- chunked compression and sparse indexes;
- live bounded progress views;
- exact tokenizer integrations;
- semantic derived summaries;
- remote-only mode.

---

## 22. Acceptance requirements

The black-box scenarios in `acceptance/SCENARIOS.md` are normative. At minimum:

1. Small output is returned completely and byte counts match.
2. Large output is bounded and explicitly marked.
3. Raw output is retrievable without rerun.
4. Failure in the middle of a long log appears in the failure projection or is indexed explicitly when failures exceed budget.
5. stdout/stderr are concurrently drained and remain separately retrievable.
6. Exit code, signal, timeout, and cancellation are preserved.
7. Exact repetition and carriage-return progress are collapsed only in projections.
8. Non-UTF-8 and binary output cannot corrupt the terminal/model result.
9. Secret fixtures are redacted before model exposure.
10. Capture quota and disk failure cannot deadlock the child.
11. A crash leaves recoverable partial evidence with explicit incompleteness.
12. Hash verification detects modification.
13. Cross-workspace retrieval is denied.
14. A local-only handoff cannot be misreported as portable.
15. Bypass returns ordinary runner behavior and requires no data migration.

---

## 23. Rollback and break-glass plan

### 23.1 Feature flags

Adapters must support:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass|shadow|enforce
OUTCTL_CAPTURE_REQUIRED=0|1
```

- `bypass`: direct existing command path.
- `shadow`: capture and measure, but return the existing unmodified tool result; for evaluation only.
- `enforce`: return bounded projection and retrieval reference.

### 23.2 Rollback procedure

1. Set adapter mode to `bypass` through the existing configuration path.
2. Reconcile/deploy configuration if served; local users can export the flag immediately.
3. Confirm commands execute through the previous runner path.
4. Retain or garbage-collect local captures according to policy.
5. Leave schemas and readers in place; no sprint/action/audit migration is required.

Because `outctl` owns no work lifecycle, rollback does not require rewriting sprintctl or actionq state.

### 23.3 Break-glass

Local `outctl inspect/slice/verify` must continue to work against the spool without Vuoro, appservice, DNS, or cluster availability. Likewise, the runner can bypass `outctl` entirely when capture infrastructure is suspected of altering command behavior.

---

## 24. Decisions resolved by this design

| Question | Decision |
|---|---|
| Where does filtering occur? | Runner/harness command boundary |
| Is full output discarded? | No, unless explicit quota/security policy says so |
| Can hidden output be recovered? | Yes, by stable capture reference without rerun |
| Is raw output durable knowledge? | No; it is evidence with retention and replica state |
| Does kctl store logs? | No |
| Does auditctl store logs? | No; compact immutable receipts and verification only |
| Does actionq retry output retrieval? | No; retrieval is read-only, command retry remains actionq/runner policy |
| Does Vuoro become the executor? | No |
| Is an LLM used to summarize command output? | Not in the core path |
| Is a daemon required? | No for v1 |
| Is cluster connectivity required? | No; local-first with optional hybrid service later |
| Are model budgets dynamic? | Caller may supply them; `outctl` enforces pinned policy and hard limits |
| Are local `_artifacts/` authoritative? | No; handoffs require host/path/hash/replica metadata |
| Can the wrapper be removed? | Yes, via adapter bypass with no authority migration |

---

## 25. Deferred decisions

These should not block Phase 1:

1. Final product/repository name.
2. Exact remote object backend.
3. Exact tokenizer integrations for each model family.
4. PTY support.
5. Compression and large-capture sparse indexing.
6. Whether retrieval is exposed through MCP, native harness tools, or both.
7. Long-term raw retention defaults after pilot measurements.
8. Whether a generic observable-resource API in Vuoro directly fronts capture references or delegates to a small registry adapter.

Each deferred choice is isolated behind the schemas and opaque reference model.

---

## 26. Recommended immediate work order

1. Accept the authority boundary and schemas as the design baseline.
2. Create the standalone `outctl` repository or a clearly isolated package under AgentOps; prefer standalone once the public contract stabilizes.
3. Implement Phase 1 locally with no service dependency.
4. Build the acceptance fixtures before command profiles.
5. Run shadow measurements on existing sessions.
6. Integrate one enforceable harness adapter.
7. Compare raw, exposed, and follow-up retrieval totals.
8. Promote policy and audit integration only after subprocess correctness is proven.

The first implementation should be boring in the favorable sense: reliable pipes, explicit manifests, deterministic slices, and very few opinions about the rest of the system. The cleverness belongs in policy profiles after the evidence layer is trustworthy.
