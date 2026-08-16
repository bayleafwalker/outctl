# Architecture decision gates

> **Closed 2026-08-16.** These gates governed the former outctl product
> direction. They remain useful for historical review only; no new wave may
> be started. The active replacement hypothesis is recorded in
> [`DISCOVERY_KILL_2026-08-16.md`](DISCOVERY_KILL_2026-08-16.md).

## Frozen direction

Hybrid Rust core plus Python adaptive layer; generic direct argv; explicit shell
only; no daemon for the MVP; compiled policy snapshot on the hot path;
trust-domain/sink information flow; safe-unredacted trusted sessions;
post-observation adaptive presentation; separate persistence and durability;
v1 compatibility before v2 promotion; retained Python reference engine; local
Linux non-PTY mature scope; external command authorization.

## Review before implementation dependency

1. Wrapper-reserved exit codes for pre-spawn failures.
2. Default capture commitment for trusted local sessions.
3. Snapshot binding, cache location, ownership, expiry, and digest checks.
4. Protected exact-secret registration channel.
5. Semantic versus byte-exact v1 writer compatibility.
6. Human renderer stdout/stderr/status behavior.
7. Exact-shell MVP scope without PTY or parent-shell state.
8. Slow-path extension isolation and sandbox requirements.

Each decision records alternatives, selected option, affected invariant,
performance/security and compatibility implications, verification, and rollback.

## Stop conditions

Stop the active wave when process parity is unexplained; contracts leak a
language ABI; the policy lattice cannot represent trusted and restricted sinks;
the fast path bypasses policy/status; required transforms occur after exposure;
capture integrity or recovery becomes ambiguous; installation collides; or a
later-wave feature is needed to make an earlier wave appear complete.
