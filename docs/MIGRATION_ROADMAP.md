# Outctl Rust/Python migration roadmap

**Status:** governing plan after the Python Phase 1 baseline  
**Provenance:** commit `1c8d6aeaa6f3526c50cb3626d6d7e301930f2b7d`  
**Rule:** complete and verify one wave before starting the next.

The Python implementation remains the compatibility reference until native
conformance and rollback gates pass. This document records the wave boundary;
it does not grant authority over scheduling, action lifecycle, audit, policy
promotion, deployment, or remote execution.

## W0 — bind and freeze the baseline

Record repository state, run Python gates, benchmark startup and projection,
and freeze raw-free metadata. No runtime behavior changes.

## W1 — decisions, v2 contracts, and conformance oracle

Land the accepted ADRs, finalize `RunRequest`, `PolicySnapshot`, `RunResult`,
and `EngineCapabilities`, define the capture-manifest delta, wrapper errors,
and cross-engine comparison rules, add canonical digest vectors, and update
dispatch protections.

Gate: examples validate; trusted and restricted sinks are representable; bypass
and unsupported outcomes are explicit; policy cannot grant command execution.

## W2 — toolchain and workspace skeleton

Add the Cargo workspace, Python control/extension layout, native
version/capabilities output, stable developer commands, CI, lazy legacy imports,
and collision-free installation. Do not execute commands in Rust.

## W3 — Rust process and v1 capture parity

Implement direct argv, process groups, timeout/cancellation, concurrent
capture, quota/finalization/recovery, v1 retrieval and verification, a
differential runner, engine selection, process-tree fixtures, and timings.

Gate: hashes and process semantics match; no deadlocks/orphans; v1 captures are
mutually readable; memory, permissions, and path safety pass.

## W4 — adaptive presentation and persistence

Implement bounded buffering with spill, streaming candidates, safe/compact/
projected/metadata renderers, savings decisions, honest persistence modes, and
native stress/benchmark suites.

## W5 — policy compiler and trust runtime

Compile source policy and commissioning context into pinned snapshots; implement
native evaluation, sink actions, claim provenance, protected exact-secret
registration, path handling, and trust-flow conformance.

## W6 — extensions and command scope

Add Python entry-point discovery, one bounded slow path, stdin and reviewed
explicit-shell modes, generic unknown commands, capability-driven unsupported
outcomes, and extension examples without Rust core edits.

## W7 — v2 storage, recovery, and hardening

Promote the manifest/index only after migration and cross-version reads are
proven. Exercise crash windows, disk failure, quota, symlink/path attacks,
tampering, garbage collection, and durability claims.

## W8 — packaging and staged rollout

Ship pinned native/Python artifacts, canary engine selection, shadow and bypass
paths, host-class conformance, rollback rehearsal, and adoption evidence. Rust
becomes default only after every earlier gate is green.

Rollback at every enabled local stage is `OUTCTL_ENABLED=0` and
`OUTCTL_MODE=bypass`; no workflow-state or capture-state migration is allowed.
