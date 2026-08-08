# Phase 1 implementation plan

This plan decomposes `IMPLEMENTATION_HANDOFF.md` into four independently
reviewable passes. Each pass begins from a clean commit, reads the declared risk
surfaces, runs targeted tests first, and finishes with the full local gate.

## Pass 1 — contracts and policy resolution

Deliver typed models for the checked-in schemas, canonical JSON, stable policy
resolution/digests, fixture generators, and direct-versus-wrapped comparison
helpers. Do not implement subprocess execution in this pass.

Falsifying gates:

- every supplied example validates against its schema;
- key ordering and equivalent YAML spellings produce the same digest;
- unknown schema versions and invalid policy combinations fail closed;
- fixtures are deterministic and record their invocation count.

## Pass 2 — capture engine and recovery

Deliver Linux non-PTY direct-argv execution, concurrent stream drainage,
process-group timeout/cancellation, bounded capture writes, chunk event index,
atomic finalization, hashes, and explicit partial recovery.

Falsifying gates: the capture, process-semantics, and recovery assertions of
acceptance A01–A04, C01–C04, and D01–D03. Projection, retrieval, and
verification assertions embedded in A01, A03, A04, and D04 are owned by Pass
3, because those capabilities are not delivered by this pass. Stress fixtures
must exceed pipe capacity on both streams and prove no leaked child remains.

## Pass 3 — projection and retrieval

Deliver deterministic normalization, redaction, selection, hard budgets, gap
markers, repeat/progress collapse, binary-safe handling, result envelopes, and
`inspect`, `slice`, `tail`, `search`, `verify`, `recover`, and `gc --dry-run`.

Falsifying gates: the deferred projection, retrieval, and verification
assertions of A01, A03, A04, and D04; acceptance A05, B01–B05, D05, E01–E08,
F01–F03, and G01–G04.
All retrieval tests prove the original fixture executed exactly once.

## Pass 4 — pilot adapter

Deliver one opt-in harness adapter with bypass, shadow, and enforce modes plus
compact receipt emission. The adapter consumes runner-owned cancellation and
identity; it creates no action lifecycle or audit authority.

Falsifying gates: acceptance H01–H03 and I01–I04, a fresh-clone installation,
and a qualitative paired Codex-or-Claude appservice health-check pilot. The
pilot records raw/exposed/retrieved bytes and token estimates, retrieval count,
wall time, wrapper overhead, policy digest, and observed direction of impact;
these metrics are decision evidence rather than release-blocking thresholds.

## Stop conditions

Stop and return a handoff instead of inventing behavior if schemas and prose
disagree; if implementation requires a daemon, database, PTY, remote executor,
cluster access, or LLM; if a test needs mutable external state; if command and
capture outcomes cannot remain distinct; or if a secret can enter model-facing
output under a supported policy.
