# Hybrid Rust and Python architecture

## Decision

Outctl will evolve incrementally into a hybrid product. Rust owns mechanically
sensitive and latency-sensitive runtime work; Python owns adaptive composition
and extension work. The migration is a compatibility bridge, not a whole-product
rewrite.

```text
policy sources + trust commissioning + extensions (Python)
                         |
                         v
             signed/digested policy snapshot
                         |
                         v
harness -> versioned RunRequest -> Rust engine -> versioned RunResult -> sink
                                   |    |
                                   |    +-> bounded adaptive presentation
                                   +------> capture / retrieval / verification
```

## Rust plane

The native plane owns direct argv execution, cwd/environment/stdin application,
process groups, signals, timeout and cancellation, concurrent stdout/stderr
drainage, bounded memory, spill and local storage, hashes, indexes, deterministic
generic projection, retrieval, verification, capability reporting, and timing
instrumentation.

It must not encode command authorization, hard-code domain sensitivity as
authority, call Python for every ordinary command, retry commands, or acquire
sprint/action/audit/knowledge ownership.

## Python plane

Python owns source policy composition, trust-context commissioning, policy
snapshot compilation, command/domain fact providers, sanitization and
projection extensions, schema migration helpers, studies, benchmarks, analysis,
and the legacy reference engine during migration.

Extensions run at commissioning/compile time or through an explicitly bounded
slow path. They receive scoped values or file descriptors, bounded input/output,
an allowlisted environment, a timeout, and no implicit access to raw captures.

## Hot-path contract

The planes exchange canonical JSON-compatible contracts rather than language
objects. The native path consumes a pinned policy snapshot and returns a
versioned result. A default simple command starts no Python interpreter.

The initial native engine must read existing v1 capture material and produce
semantically compatible v1 results before v2 becomes default. Cross-engine
conformance fixtures define exact fields, semantically equivalent fields, and
explicitly permitted differences.

## Adaptive presentation

Projection is not automatically beneficial. The renderer compares safe raw
output with the bounded projection after output is observed. It selects among:

- empty-success;
- raw-safe output;
- compact failure;
- bounded projected output;
- metadata-only or denied output required by sink policy.

The comparison includes envelope overhead and minimum absolute/ratio savings.
Required sink transforms always run before exposure. Spill and persistence do
not alter exact bytes or process semantics.

## Rollback

The Python engine remains selectable until native conformance and rollout gates
are complete. `OUTCTL_ENABLED=0` restores the ordinary harness path. Captures
remain readable across rollback; no workflow-state migration is required.
