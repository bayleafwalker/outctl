# ADR-0002: Hybrid Rust execution plane and Python adaptive plane

**Status:** Accepted
**Date:** 2026-08-10

Use Rust for the command hot path, process semantics, capture, generic
projection, retrieval, verification, and local storage. Retain Python for policy
composition, trust commissioning, extensions, studies, analysis, compatibility,
and the migration reference engine. Communicate through stable versioned
contracts; do not make per-command Python startup or an in-process FFI bridge a
default-path requirement.

This balances semantic robustness and startup cost with the ecosystem's need
for adaptable policy and integrations. Rollback selects the Python engine.
