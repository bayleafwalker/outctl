# Contracts and compatibility

W1 freezes four language-neutral v2 families:

| Family | Direction | Owner of meaning |
|---|---|---|
| `RunRequest` | runner → engine | runner/harness |
| `PolicySnapshot` | Python control → engine | policy/trust compiler |
| `RunResult` | engine → sink | outctl, with command status distinct |
| `EngineCapabilities` | engine → negotiator | selected engine |

The capture manifest is a separate evidence contract. The v2 delta records the
frozen policy snapshot ID/reference/digest triple alongside engine, commitment,
durability, presentation, and compatibility metadata while retaining v1 raw
stream fields and one-version-back reads.

Compatibility rules:

1. v1 captures remain readable throughout the migration window.
2. Canonical JSON and digest vectors are independent of Python and Rust.
3. Cross-engine fields are classified as exact, semantic, or intentional
   versioned differences; no unclassified difference passes.
4. Capabilities are negotiated before shell, stdin, persistence, retrieval, or
   extension features are used.
5. Unsupported, bypassed, rejected, and capture-failed outcomes are explicit.
6. Retrieval never reruns a command and engine rollback never migrates a
   capture.

W1 additionally freezes these cross-document bindings and compatibility
claims:

- a request carries `snapshot_id`, policy reference, and policy digest;
  `RunResult` echoes the exact triple and the cache entry carries the same
  snapshot ID;
- commissioned trusted-local snapshots require host-persistent (or stronger)
  capture by default;
- exact secrets use only opaque `secret://` references;
- the Python reference is the only v1 writer, while v2 preserves exact v1
  stream bytes without claiming byte-exact v1 manifest serialization;
- direct argv is the W1 baseline and explicit shell remains a negotiated,
  unsupported capability in the W1 engine.

W5 implements native `RunRequest`/`PolicySnapshot` evaluation without claiming
that the W4 capture envelope is a v2 `RunResult` writer. Capability metadata
advertises those two evaluated families and leaves `run_result` empty until its
writer and manifest compatibility boundary are implemented. The canonical W5
snapshot under `examples/v2` is compiled by Python and revalidated by Rust as a
cross-language digest and sink-action vector.

W6 adds a digest-bound `command_scope` to that snapshot. Direct argv remains
generic. Explicit shell use must match one complete reviewed interpreter argv,
and stdin must match one compiled mode. Requests carry separate PTY,
live-output, and parent-shell-state requirements; the W6 native engine
advertises all three as unsupported and rejects them before spool creation. The
native library supports opaque process-memory stdin references, while the
ordinary CLI exposes only `none` and explicit `inherit` and starts no Python.

Extension protocol documents are outside `RunRequest` and `RunResult`. A
commissioning invocation is bound to a context digest; a projection invocation
is bound to the exact policy snapshot ID/reference/digest triple. Accepted
commissioning fact records are sorted and included in `source_digest` material.
No-extension compilation preserves the no-extension vector.
