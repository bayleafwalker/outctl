# Threat model: `outctl`

## Assets

- command stdout/stderr, potentially containing credentials or customer/project data;
- exact invocation metadata;
- action/sprint/session bindings;
- capture and policy integrity;
- local disk availability;
- model context integrity;
- cross-host replica authorization.

## Trust boundaries

1. Command process -> capture pipeline: command output is untrusted.
2. Capture pipeline -> local spool: filesystem and quota boundary.
3. Raw capture -> projection: normalization and redaction boundary.
4. Local host -> remote replica/backend: authorization and data-classification boundary.
5. Result envelope -> model: prompt-injection and context-volume boundary.
6. Capture reference -> retrieval API: workspace/actor authorization boundary.

## Threats and required controls

### T1. Secret leakage into model context

**Examples:** bearer tokens, connection strings, private keys, cookies, database URLs.

**Controls:** exact-value secret registration, regex/structured redaction, overlap-aware streaming matcher, environment minimization, argv display redaction, redaction before model exposure, tests with boundary-spanning secrets.

**Residual risk:** unknown secrets may evade pattern matching. Exact local raw therefore remains sensitive and short-lived.

### T2. Secret replication off-host

**Controls:** sanitized replica is the default; exact replica requires explicit policy and authorized backend; replica class is recorded; never equate sanitized and exact hashes.

### T3. Terminal/control-sequence attacks

**Examples:** ANSI escapes, OSC clipboard/title sequences, carriage-return rewriting, malicious hyperlinks.

**Controls:** raw bytes never emitted directly to the model/UI; projection strips or renders control sequences safely; binary detection; bounded line length.

### T4. Prompt injection through command output

**Controls:** adapters preserve a typed tool-result boundary and provenance header; output is treated as data; no instruction execution during projection; retrieval tools are read-only.

### T5. Artifact tampering

**Controls:** SHA-256 hashes for streams, event index, projection, and manifest; atomic finalization; verification command; expected versus observed digest retained; audit verification receipt.

### T6. Path traversal or symlink replacement

**Controls:** fixed spool root; `openat`-style safe creation where practical; reject symlinked capture directories; mode 0700/0600; canonical workspace checks; atomic rename; no arbitrary file reads from a capture reference.

### T7. Cross-workspace disclosure

**Controls:** capture metadata includes workspace and actor scope; retrieval authorizes against both; registry does not resolve a digest alone without access context; local CLI defaults to current user and workspace.

### T8. Disk exhaustion

**Controls:** per-command and per-workspace quotas; streamed quota accounting; garbage collection; fail-open/fail-closed policy; continue draining pipes even after storage quota is reached; visible degraded state.

### T9. Memory exhaustion or deadlock

**Controls:** bounded queues, chunked reads, concurrent stdout/stderr drainage, max projection line length, no full-output buffering.

### T10. Wrapper changes command behavior

**Controls:** direct argv execution, explicit shell mode, no PTY in v1, signal/process-group tests, bypass mode, conformance fixtures comparing wrapped and direct execution.

### T11. Misleading completeness

**Controls:** separate command and capture statuses; explicit `truncated`, `incomplete`, `expired`, `redacted`, and `sanitized` flags; byte offsets at quota boundary; portable/local-only handoff labels.

### T12. Retrieval triggers execution

**Controls:** retrieval APIs are read-only and operate only on resolved capture material; a missing capture returns unavailable, never automatic rerun.

### T13. Policy drift

**Controls:** execution envelope pins policy digest; result manifest records the digest; kctl records active-policy decisions; policy files are maintained in Git.

### T14. Audit flooding

**Controls:** local interactive captures are not promoted by default; action-bound receipts are compact; retrieval events can be aggregated; raw bodies never enter the ledger.

## Security acceptance minimum

- secret fixtures do not appear in model projection or sanitized replica;
- a secret split across read chunks is still redacted;
- ANSI/OSC fixtures cannot alter the terminal outside printable projection text;
- modified raw files fail verification;
- a different workspace cannot resolve or read a capture;
- quota exhaustion does not deadlock the child;
- exact/raw and sanitized replica classes remain distinguishable.
