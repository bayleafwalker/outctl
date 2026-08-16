# Outctl target architecture

> **Archived 2026-08-16.** This architecture was superseded by the
> [`DISCOVERY_KILL_2026-08-16.md`](../DISCOVERY_KILL_2026-08-16.md) decision.
> Do not implement its Rust/Python product roadmap. Preserve this document as
> a historical record of the killed thesis.

**Status:** Historical accepted direction; frozen
**Accepted:** 2026-08-10; retired 2026-08-16
**Applies after:** the completed Python Phase 1 baseline
**Source package SHA-256:** `ec1d947b6e9559617191dfd30c89562a07925e358264200380085ea966c01977`

This directory is the stable architectural entry point for outctl's evolution
from the Python proof of concept into a mature hybrid product. The package was
verified against both the operator-supplied digest and its internal
`SHA256SUMS`. Repository HEAD, current tests, and current contracts remain the
baseline; the source package is directional guidance, not permission to erase
newer work.

## Accepted direction

- A Rust execution and data plane owns the command hot path, process semantics,
  bounded capture, adaptive presentation, retrieval, and verification.
- Python remains the adaptive/control plane for policy authoring, trust-context
  assembly, extensions, studies, analysis, compatibility, and experimentation.
- Language-neutral, versioned contracts separate the two planes. There is no
  per-command Python startup on the default native path and no in-process FFI
  dependency between them.
- Generic direct argv remains the universal baseline. Explicit shell execution
  is a separately declared capability; adapters add facts and projections but
  never authorization.
- Presentation is selected after observing output. Small output may be returned
  directly when that is cheaper and safe; noisy output receives a bounded,
  explicit projection with recoverable evidence.
- Information flow is trust-domain and sink specific. Classification does not
  imply concealment inside a commissioned trusted session; export and
  lower-trust sinks may sanitize, reduce to metadata, or deny.
- Persistence commitment and durability are separate. Receipts never overstate
  whether evidence is memory-only, process-local, host-persistent, replicated,
  or durable-authoritative.
- Unsupported modes and capture failures use an explicit reject, recorded
  bypass, or declared fallback. No silent semantic fallback is allowed.
- `OUTCTL_ENABLED=0` and engine selection provide rollback without workflow or
  capture-state migration.

## Product scope

The mature MVP targets finite Linux non-PTY local commands, including high
invocation counts, unexpectedly noisy output, timeout/cancellation, nonzero
exit, storage failures, wrapper crashes, and child-process-tree handling. PTY,
indefinite follow/watch, remote execution, served capture registries, semantic
LLM summarization, and dynamically loaded native plugins remain outside the
MVP.

Outctl continues to own capture, projection, retrieval, verification, and
retention mechanics only. Command authorization, scheduling, action lifecycle,
work state, audit judgment, curated knowledge, and remote execution remain with
their existing owners.

## Normative documents

- [Hybrid architecture](HYBRID_ARCHITECTURE.md)
- [Trust and information flow](TRUST_AND_INFORMATION_FLOW.md)
- [Contracts and compatibility](CONTRACTS_AND_COMPATIBILITY.md)
- [Migration roadmap](../MIGRATION_ROADMAP.md)
- [Decision gates](../DECISION_GATES.md)

The four accepted ADRs are under [`docs/adr/`](../adr/). Existing
[`DESIGN.md`](../DESIGN.md), [`THREAT-MODEL.md`](../THREAT-MODEL.md), and
[`acceptance/SCENARIOS.md`](../../acceptance/SCENARIOS.md) remain the normative
Python v1 baseline until a gated v2 contract replaces each promise.
