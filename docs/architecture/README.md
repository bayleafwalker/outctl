# Outctl target architecture

This is the W1 contract boundary for the post-baseline migration. Rust owns
mechanically sensitive hot-path work; Python remains the adaptive/control plane
and reference engine. The existing Python v1 behavior stays normative until a
later wave proves compatibility.

Read with:

- [hybrid architecture](HYBRID_ARCHITECTURE.md)
- [trust and information flow](TRUST_AND_INFORMATION_FLOW.md)
- [contracts and compatibility](CONTRACTS_AND_COMPATIBILITY.md)
- [wrapper errors and comparison](WRAPPER_ERRORS_AND_COMPARISON.md)
- [decision gates](../DECISION_GATES.md)
- [migration roadmap](../MIGRATION_ROADMAP.md)

The native path consumes a pinned `PolicySnapshot` and exchanges only the
versioned contracts under `schemas/v2/`. It must not acquire command
authorization, scheduling, action lifecycle, audit judgment, curated
knowledge, or remote-execution authority.
