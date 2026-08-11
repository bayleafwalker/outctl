# W1 decision gates

**Status:** frozen for re-review — 2026-08-11  
**Scope:** contracts, conformance oracles, and architecture decisions only.
W1 does not add Cargo, Rust, runtime, deployment, queue, audit, or Sprintctl
changes. The Python v1 engine remains the compatibility reference.

Each gate below has one selected option. The invariant is normative; the
verification is the falsifying check; and the rollback is the action that
removes the W1 contract consumer without migrating workflow or capture state.

## G1 — wrapper exit mapping

**Selected option:** `RunResult` is the authoritative structured result. A CLI
wrapper returns the child status when the child started and capture did not
fail; a signalled child maps to `128 + signal`. A pre-spawn wrapper error or a
post-spawn capture failure returns wrapper status `125`. A truncated or
degraded-but-usable capture is not a wrapper failure and preserves the child
status. The child exit code, signal, timeout, cancellation, capture status,
and wrapper error remain separate fields.

**Invariant:** no wrapper error rewrites the child fields, and no child status
is reported when the command did not start. JSON/JSONL output is authoritative
over the process exit code.

**Verification:** validate every error code/phase pairing; reject results that
claim `unsupported`/`rejected` after spawn, combine exit code and signal, or
report a post-spawn capture failure as a successful complete capture. Exercise
the mapping against direct v1 behavior in the later process-parity gate.

**Rollback:** stop consuming the v2 result and run the Python v1 path with
`OUTCTL_ENABLED=0 OUTCTL_MODE=bypass`; do not reinterpret or rewrite captures.

## G2 — trusted default capture

**Selected option:** a commissioned `trusted-local` snapshot defaults to
`host-persistent` commitment, `host` durability, and `required=true` capture.
`replicated` is an explicit stronger choice. `memory-only` and
`process-local` are not valid defaults for trusted-local execution.

**Invariant:** commitment and durability are one ordered contract:
`memory-only/process-local -> none`, `host-persistent -> host`, and
`replicated -> replica/authoritative`. A required capture must survive the
process (`host-persistent` or `replicated`). Capture commitment is independent
of presentation; safe small output does not waive required capture.

**Verification:** schema tests reject contradictory commitment/durability
pairs, required ephemeral capture, and uncommissioned trusted-local sessions;
the example snapshot proves the selected default.

**Rollback:** use the v1 local capture behavior or bypass. No capture-state
migration, replay, or retention conversion is permitted.

## G3 — policy snapshot cache and binding

**Selected option:** the Python control plane owns an in-process/workspace
cache of immutable snapshots. The cache key contains `snapshot_id`; the entry
also records that ID, policy reference, policy digest, source digest, issue
time, and expiry. A request binds all three of `snapshot_id`, `policy_ref`, and
`policy_digest`; the engine accepts only an exact match and never compiles or
widens policy on the hot path. Results and capture deltas echo the binding.

**Invariant:** cache hits are usable only before `expires_at` and only when
all binding digests match. A digest mismatch, expired entry, wrong workspace
scope, or missing snapshot is a pre-spawn rejection. The snapshot may constrain
execution and disclosure but cannot authorize execution, retry, or lifecycle
state.

**Verification:** cross-contract tests mutate each ID/reference/digest and
assert rejection; schema tests reject missing cache ownership/expiry fields;
digest vectors prove canonical, engine-independent binding material.

**Rollback:** discard the v2 cache consumer and use the Python v1 policy path;
no cache or capture migration is needed.

## G4 — protected secret channel

**Selected option:** exact secret values are registered through a protected,
opaque secret channel owned by the runner/control-plane boundary. Contracts
carry only `secret://` references and channel mode; exact values are never in
`RunRequest`, `PolicySnapshot`, `RunResult`, receipts, examples, digests, or
ordinary model-facing output. The engine receives match material only through
the protected registration API and redacts before any restricted/export sink.

**Invariant:** JSON contracts cannot authorize or transport a secret value.
`secret_channel.mode=none` has no references; `protected-opaque` has one or
more opaque references. A lower-trust sink cannot request safe-unredacted
disclosure.

**Verification:** schema and fixture scans reject secret-value fields and
trust/disclosure contradictions; later capture tests cover chunk-boundary
redaction and sanitized-replica separation.

**Rollback:** disable v2 secret-channel consumption and retain v1 redaction;
never copy exact values into a fallback contract or artifact.

## G5 — v1 writer stance

**Selected option:** Python v1 remains the only v1 manifest writer during the
migration window. A v2 writer emits the additive v2 capture-manifest delta and
preserves exact v1 stdout/stderr stream bytes for existing readers; it does not
claim byte-exact v1 manifest serialization or become a v1 writer.

**Invariant:** v1 reader compatibility is semantic plus exact stream bytes;
the v1 manifest format and writer remain untouched. Every delta identifies
`python-reference-only` as the v1 writer stance and sets
`v1_manifest_byte_exact=false`.

**Verification:** delta schema/tests reject a byte-exact v1-writer claim and
require preserved stream bytes; the existing v1 reader and full Python suite
remain green.

**Rollback:** select the Python v1 reader/writer path. Do not rewrite existing
manifests or migrate capture directories.

## G6 — renderer streams and status

**Selected option:** machine mode writes exactly one structured result to
stdout and diagnostics only to stderr. Human mode writes the bounded rendered
projection to stdout; status, omission/retrieval footer, and renderer
diagnostics go to stderr. Child stdout/stderr are never live-passthrough
streams; provenance is represented in the rendered projection. Exit mapping is
G1.

**Invariant:** no raw bytes, control sequences, secret values, or unbounded
text can enter either model-facing stream. A renderer cannot change the
structured command/capture outcome.

**Verification:** renderer contract tests assert stdout/stderr separation,
bounded output, and stable status behavior; control-sequence and binary
fixtures remain safe.

**Rollback:** use the v1 JSON envelope/ordinary runner output; do not replay
captured raw streams into a terminal.

## G7 — shell scope

**Selected option:** direct argv is the W1/W2 universal baseline. Explicit shell
is represented in the contract but unsupported by the W1 engine and must be
advertised as `explicit_shell=false`. No implicit shell, PTY, parent-shell
state, shell fallback, or shell interpolation is allowed. A future explicit
shell capability is a separately negotiated W6 feature with an explicit
interpreter and reviewed policy.

**Invariant:** direct-argv requests have no shell command; explicit-shell
requests have an explicit shell command and cannot silently become direct argv.
Unsupported is a pre-spawn outcome.

**Verification:** schema tests reject mode/field contradictions and conformance
tests reject silent fallback; capability examples keep `explicit_shell=false`.

**Rollback:** bypass to the existing Python v1 direct-argv runner. No shell
state is persisted or restored.

## G8 — slow-path isolation

**Selected option:** Python extensions run only at commissioning or through an
explicit bounded, isolated slow path. The slow path uses bounded JSON IPC,
deadline and resource limits, a minimal environment, no inherited secret
values, no network, no spool access, and no command/process creation. It may
return facts, policy candidates, projection candidates, or sanitizer results;
it cannot authorize execution, retry, persistence, or lifecycle actions.

**Invariant:** the Rust/Python hot path remains runnable when the slow path is
absent, times out, crashes, or returns malformed data. Slow-path output is
untrusted input and cannot widen a pinned snapshot or bypass required
transforms.

**Verification:** the W1 boundary/oracle tests assert the allowed output class
and failure isolation; implementation and resource-limit tests are deferred
to W6 and cannot be pulled into W1.

**Rollback:** disable extensions/slow path and continue with the pinned
snapshot and deterministic core projection. No workflow or capture migration.

## W1 stop gate

Do not start W2 if any schema permits a contradiction above, a digest binding
is not exact, a secret value crosses the contract boundary, a v1 writer claim
changes, or a rollback requires workflow/capture-state migration. W2 remains
out of scope until this document, the v2 examples, and the conformance tests
are accepted together.
