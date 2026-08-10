# Contracts and compatibility

## Contract families

The hybrid boundary is defined by four v2 contract families:

- `RunRequest`: argv or explicit shell mode, cwd, environment/stdin policy,
  cancellation/timeout binding, identity, sink, and pinned policy snapshot.
- `PolicySnapshot`: canonical policy rules, trust context, sink lattice,
  capture/persistence choices, provenance, digest, and expiry/session binding.
- `RunResult`: command and capture outcomes, presentation choice, bounded body,
  evidence reference, sizes/hashes, policy provenance, timings, and warnings.
- `EngineCapabilities`: supported contract versions, process modes, storage and
  retrieval features, platform, engine identity, and limits.

The capture manifest remains a separate evidence contract. V2 may extend its
indexes and durability metadata, but must preserve honest completeness and
existing v1 readability through the compatibility window.

## Compatibility rules

1. Freeze golden v1 captures and process fixtures before introducing v2.
2. Define canonical JSON and digest vectors independent of Python or Rust.
3. Classify each cross-engine field as exact, semantically equivalent, or an
   intentional versioned difference.
4. Negotiate capabilities before using explicit shell, stdin, persistence,
   retrieval, or extension features.
5. Unsupported behavior returns a typed outcome; it never silently changes
   execution semantics.
6. The Rust engine first proves v1 read/write semantic compatibility. V2 is
   alpha until consumer tests and rollback are exercised.
7. Retrieval never reruns and engine rollback never requires capture migration.

Wrapper-reserved exit codes, default capture commitment, policy snapshot cache,
exact-secret registration, v1 writer exactness, human renderer streams,
explicit-shell MVP scope, and slow-path isolation are review gates before code
depends on them.
