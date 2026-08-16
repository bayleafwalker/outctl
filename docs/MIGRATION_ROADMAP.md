# Outctl migration roadmap

> **Retired 2026-08-16.** This roadmap is closed and must not be advanced. The
> product thesis was killed after native Code Mode evidence and the native
> versus outctl commissioning comparison. See
> [`DISCOVERY_KILL_2026-08-16.md`](DISCOVERY_KILL_2026-08-16.md).

**Status:** Historical, closed
**Rule:** Complete and verify one wave before starting the next. Repository HEAD
and its tests are authoritative.

## W0 — bind and freeze the baseline

Record HEAD/status/worktrees, run the full Python gates, benchmark direct,
installed-Python, and `uv run` fresh-process startup, profile empty/one-line
commands, freeze raw-free golden metadata and local-only raw fixture references,
and publish baseline reports. No runtime behavior changes.

Gate: existing behavior reproduces; performance reports include p50/p95/p99 and
a 1,000-command projection; no raw operational data or secrets enter Git.

## W1 — decisions, v2 contracts, and conformance oracle

Land the accepted ADRs, finalize the four v2 contract families and capture
manifest delta, define wrapper errors and cross-engine comparison rules, add
canonical digest vectors, and update dispatch protections.

Gate: examples validate; trusted and restricted policies are representable;
bypass and unsupported results are explicit; policy cannot grant execution.

## W2 — toolchain and workspace skeleton

Add the Cargo workspace and Python control/extension package layout, native
version/capabilities output, stable developer commands, CI, lazy legacy imports,
and collision-free installation. Do not execute commands in Rust yet.

## W3 — Rust process and v1 capture parity

Implement direct argv, process groups, timeout/cancellation, concurrent capture,
quota/finalization/recovery, v1 retrieval and verification, a differential
runner, engine selection, child/grandchild fixtures, and stage timings.

Gate: hashes and process semantics match; no deadlocks/orphans; v1 captures are
mutually readable; memory, permissions, and path safety pass.

## W4 — adaptive presentation and persistence

Implement bounded exact buffering with spill, generic streaming candidates,
raw-safe/compact/projected/metadata renderers, minimum savings decisions,
honest persistence/durability modes, and native stress/benchmark suites.

## W5 — policy compiler and trust runtime

Compile source policy and commissioning context into pinned snapshots; implement
native evaluation, sink actions, claim provenance, protected exact-secret
registration, path handling, policy explain/lint, and trust-flow conformance.

## W6 — extensions and command scope

Add Python entry-point discovery and compile-time contributions, one bounded
slow-path protocol, stdin and reviewed explicit-shell modes, generic unknown
commands, capability-driven unsupported outcomes, and example Kubernetes/custom
extensions without a Rust core edit.

## W7 — v2 storage, recovery, and hardening

Promote the capture manifest/index only after migration and cross-version reads
are proven. Exercise crash windows, disk failure, quota, symlink/path attacks,
tampering, garbage collection, and durability claims.

## W8 — packaging and staged rollout

Ship pinned native and Python artifacts, canary engine selection, shadow and
bypass paths, host-class conformance, rollback rehearsal, and adoption evidence.
Rust becomes default only for the supported capability set after every prior
gate is green.

## Backlog alignment

Backlog items must map to exactly one wave or an explicit post-MVP lane. Existing
Python Phase 1 and controlled-pilot items retain their historical outcome; they
must not be reopened as if the prototype had not shipped. New migration items
use the W0-W8 dependencies above and preserve these coordinator-owned decisions:
process semantics, evidence integrity, redaction/information flow, schema and
test-oracle authorship, compatibility, migration, recovery, and release.
