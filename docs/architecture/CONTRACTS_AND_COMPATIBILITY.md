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

W7 promotes the native writer only when the structured result and additive
capture delta can be committed together without weakening the migration
contract. A completed result may describe a complete, truncated,
degraded-but-usable, or recovered-incomplete capture. Only a capture failure
that makes the required evidence unusable is a `capture-failed` wrapper
outcome; a degraded usable capture preserves the child result and has no
wrapper error.

The additive v2 delta binds `base_manifest_digest`, the exact immutable base
manifest bytes, to the request,
policy snapshot, engine, stream and event-index digests, capture status,
presentation, persistence commitment, and durability evidence. Host durability
requires synced artifacts, a synced partial directory, atomic rename, and a
synced destination parent. An immutable publication record is written only
after that parent sync and binds the exact v2 sidecar digest. Strict v2 reads,
verification, recovery, collection, and index rebuild reject a visible but
unpublished capture as uncommitted evidence. The local index is explicitly
non-authoritative and rebuildable. Recovery metadata never invents the
command's final status.

Retention is a separate record so expiry cannot change the immutable capture
digest. An expiry tombstone pins the original capture reference and exact v2
sidecar digest (or the base digest for a one-back capture), the manifest
digest, authoritative prior capture status, bounded retention policy identity
and reason, and the resulting unavailable state.
It never authorizes an automatic rerun. Existing v1 manifests are not rewritten:
Python remains the only v1 writer, new v2 captures preserve exact v1 stream
bytes and a v1-readable layout, and the native reader supports one-version-back
captures throughout the migration window.

Filesystem paths are never compatibility identifiers or evidence authority.
Migration, recovery, index rebuild, verification, and collection operate from
pinned directory descriptors and fail closed on unsafe replacement. In
particular, POSIX does not provide a race-free conditional `rmdir` for a legacy
empty directory that a same-UID process can replace. A collector may remove a
legacy W4 tombstone only while it holds exclusive spool ownership; otherwise it
retains the directory safely. New ephemeral capture paths must leave no named
empty capture directory to collect.
