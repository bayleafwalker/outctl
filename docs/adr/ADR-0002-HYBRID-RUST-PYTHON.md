# ADR-0002: Hybrid Rust execution plane and Python adaptive plane

**Status:** Accepted — 2026-08-10

Use Rust for command hot-path process semantics, capture, deterministic
projection, retrieval, verification, and local storage. Retain Python for
policy composition, trust commissioning, extensions, studies, analysis,
compatibility, and the migration reference engine. Communicate through the
versioned JSON contracts; do not require per-command Python startup or FFI.
