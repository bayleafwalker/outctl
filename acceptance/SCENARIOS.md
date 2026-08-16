# Black-box acceptance scenarios

> **Archived 2026-08-16.** These scenarios are preserved for historical
> regression and discovery only. They are not an authorization to extend the
> outctl product or run a new efficacy study. See
> [`../docs/DISCOVERY_KILL_2026-08-16.md`](../docs/DISCOVERY_KILL_2026-08-16.md).

These scenarios are normative for Phase 1 unless marked later-phase.

## A. Correctness and completeness

### A01 — small stdout

Command emits 20 UTF-8 lines and exits 0.

Expected:

- projection contains all lines in order;
- `truncated=false`;
- stdout hash and byte count match fixture;
- stderr count is zero;
- command exit is 0 and capture is complete.

### A02 — small stderr and nonzero exit

Command emits diagnostics only to stderr and exits 7.

Expected:

- diagnostics appear;
- command exit is exactly 7;
- capture status is complete;
- wrapper does not turn command failure into capture failure.

### A03 — large stdout

Command emits at least 100,000 numbered lines with a unique marker near the middle.

Expected:

- projection stays within every configured budget;
- omission is explicit;
- capture reference is present;
- `slice` retrieves the middle marker;
- the command fixture records one execution only.

### A04 — mixed stdout/stderr

Command emits large data to both streams concurrently.

Expected:

- no deadlock;
- both raw streams are complete and separately retrievable;
- event index sequence is monotonic;
- merged projection labels stream provenance where needed.

### A05 — failure buried in noise

Command emits 20,000 passing lines, a traceback around line 10,000, then 5,000 cleanup lines, and exits 1.

Expected:

- failure projection contains traceback and context under default test/failure policy;
- final summary/tail is present;
- if too many failures exceed budget, an explicit failure index and retrieval command are present.

## B. Projection behavior

### B01 — consecutive repetition

Command emits the same line 10,000 times.

Expected:

- raw output contains all lines;
- projection contains representative text plus exact repeat count/range;
- repetition collapse is recorded.

### B02 — carriage-return progress

Command writes 10,000 progress updates using `\r`, then a final success line.

Expected:

- raw bytes are exact;
- projection contains bounded representative progress and final state;
- no control sequence can rewrite prior tool output.

### B03 — giant line

Command emits a single 5 MiB line.

Expected:

- raw output is retained within quota;
- projection line is clipped under the configured maximum and explicitly marked;
- memory remains bounded.

### B04 — non-UTF-8

Command emits invalid UTF-8.

Expected:

- raw hash matches exact bytes;
- projection records decoder/replacement behavior;
- no crash.

### B05 — binary

Command emits NUL-rich random bytes.

Expected:

- projection switches to binary-safe metadata/excerpts;
- terminal/model output contains no unsafe raw control bytes;
- capture is retrievable by byte range.

## C. Process semantics

### C01 — timeout

Command ignores ordinary completion and exceeds timeout.

Expected:

- configured signal sequence is sent;
- timeout and signals are recorded;
- final observed output is captured;
- process group has no leaked child.

### C02 — caller cancellation

Runner cancels a running command.

Expected:

- cancellation is distinct from timeout;
- signal escalation is recorded;
- actionq remains responsible for action outcome.

### C03 — shell semantics

Run argv containing spaces, glob characters, and `$` without shell mode.

Expected:

- arguments reach the child literally;
- no implicit expansion.

Explicit shell mode must be separately tested and recorded.

### C04 — wrapped versus direct

Run a fixture directly and through `outctl`.

Expected:

- same child exit status;
- same raw stdout/stderr bytes for non-PTY fixtures;
- no environment/cwd drift beyond documented wrapper variables.

## D. Storage and recovery

### D01 — command capture quota

Command exceeds max capture bytes.

Expected:

- explicit `CAPTURE_TRUNCATED` with last offsets;
- child pipes continue to drain or child is cancelled in required mode;
- no deadlock;
- result never claims complete capture.

### D02 — disk full/write failure

Inject storage failure after command starts.

Expected:

- interactive fail-open mode returns capture warning and command result;
- required mode cancels/fails closed;
- command and capture statuses remain separate.

### D03 — wrapper crash

Kill wrapper after partial output.

Expected:

- `recover` identifies partial capture;
- recovered manifest is explicitly incomplete;
- unknown final command status is not invented.

### D04 — tampering

Modify one raw byte after finalization.

Expected:

- `verify` fails and reports expected/observed digest;
- manifest is not silently rewritten.

### D05 — garbage collection

Expire a raw capture while retaining its manifest/tombstone according to policy.

Expected:

- retrieval reports expired/unavailable;
- no automatic rerun;
- durable receipt can still identify what existed and why it expired.

## E. Security

### E01 — exact secret

Command prints a registered secret value.

Expected:

- exact local raw behavior follows policy;
- model projection never contains the secret;
- receipt records rule ID/count, not secret value.

### E02 — split secret

Secret spans two read chunks.

Expected:

- model projection and sanitized replica redact it fully.

### E03 — ANSI/OSC injection

Command prints terminal title, clipboard, hyperlink, cursor movement, and clear-screen sequences.

Expected:

- raw bytes preserved;
- projection neutralizes sequences;
- surrounding terminal output is unaffected.

### E04 — path traversal/symlink

Attempt to resolve a capture through a symlink or `..` path outside spool/workspace.

Expected:

- denied;
- no arbitrary file read/write.

### E05 — cross-workspace retrieval

Actor from another workspace requests a known capture ID/digest.

Expected:

- denied even if digest is known.

## F. Ecosystem integration

### F01 — action retry

Actionq retries one command.

Expected:

- each attempt has a distinct capture ID;
- both bind to the action with attempt number;
- `outctl` performs no retry itself.

### F02 — audit promotion

Promote one capture as acceptance evidence.

Expected:

- auditctl receives compact hashes/status/policy/locator metadata;
- raw body is not embedded;
- verification result is independently recorded.

### F03 — local-only handoff

Create a handoff with no replica.

Expected:

- it states source host/path/hash and `local-only`;
- receiving host cannot mistake it for portable evidence.

### F04 — portable handoff (later phase)

Replicate capture to receiving host/backend.

Expected:

- replica class and digest verified;
- receiving host resolves opaque reference;
- exact versus sanitized class remains visible.

### F05 — bypass

Set `OUTCTL_MODE=bypass`.

Expected:

- runner uses pre-wrapper path;
- no state migration;
- existing captures remain readable/GC-able.

## G. Economics

### G01 — measured long-session class

Replay representative Bash output totaling approximately 178.8k estimated tokens.

Expected:

- raw capture remains available within quota;
- model-facing projection total drops by at least 50%;
- report includes raw/exposed/retrieved estimates and policy digests;
- all retrievals use existing captures rather than reruns.

## H. Pilot adapter modes

### H01 — bypass preserves the existing path

Run the selected Codex or Claude harness pilot with bypass selected.

Expected:

- the harness uses its ordinary pre-wrapper command path;
- no new capture or receipt is created by the adapter;
- existing captures remain inspectable and eligible for dry-run GC;
- no action, sprint, or audit state is created or migrated.

### H02 — shadow measures without changing the ordinary result

Run the selected harness with shadow selected for the same command corpus.

Expected:

- command semantics and the harness's ordinary result remain equivalent to the
  bypass run;
- capture/projection metrics are available locally under the pinned policy;
- command and capture outcomes remain distinct;
- shadow does not retry commands or determine action/audit outcomes.

### H03 — enforce exposes bounded evidence

Run the selected harness with enforce selected for an output-heavy command.

Expected:

- model-facing output is a bounded, redacted projection plus opaque retrieval
  capability/reference, never raw capture bytes or paths;
- capture-required behavior remains independent from command outcome;
- omitted evidence can be retrieved from the existing capture without rerun.

## I. Pilot integration evidence

### I01 — caller-owned context and authority

Run the adapter with pinned policy reference/digest, cwd, host/harness identity,
and caller-provided action, sprint, session, and correlation bindings.

Expected:

- supplied context appears unchanged in the envelope/receipt as appropriate;
- the adapter does not create workflow state, retry commands, or determine
  action/audit terminal outcomes;
- runner-owned cancellation remains distinct from timeout.

### I02 — cancellation and incomplete evidence

Cancel an active adapter invocation with a child process group.

Expected:

- the child group is terminated according to runner policy and observed pipes
  are drained;
- recovery records explicit incomplete evidence and does not invent a final
  command/action outcome;
- timeout metadata is distinguishable from caller cancellation.

### I03 — bounded no-rerun retrieval bridge

Use an enforced output that omits a known middle marker, then retrieve it by
capture reference through the selected harness boundary.

Expected:

- retrieval returns bounded/redacted evidence from the existing capture;
- the fixture invocation count remains exactly one;
- no generic command executor or wrapped command rerun is invoked.

### I04 — qualitative Codex/Claude appservice health-check pilot

Run a paired baseline and opt-in pilot through Codex or Claude using an
appservice health-check workflow based on `kubectl` output. Select the command
corpus from representative local session evidence without storing raw session
or command output in Git.

Expected:

- the report records policy digest, command class, raw/exposed/retrieved byte
  and token estimates, retrieval count, wall time, and wrapper overhead;
- it states the observed direction of context reduction and operational impact,
  including failures/truncations/bypasses, without a release-blocking numeric
  threshold;
- raw output remains outside Git, sprintctl, kctl, auditctl, and the report;
- a fresh clone can install the selected adapter/pilot path and reproduce the
  local evidence fixture.
