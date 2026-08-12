# W7 v2 storage, recovery, and hardening handoff

**Status:** implementation candidate; independent review pending
**Backlog:** Outctl #2139
**Baseline:** `origin/main` at `6d6d9a47bb2b425df9de8e353fe9a0a727c03de8`

## Contract boundary

W7 promotes native v2 storage only after migration-window readability,
recovery, integrity, retention, and durability claims are proven under injected
faults. The promoted writer must emit an authoritative v2 `RunResult` and an
additive v2 capture-manifest delta bound to the exact request digest, policy
snapshot ID/reference/digest, engine, capture status, stream and event-index
digests, presentation, commitment, and durability evidence.

The base evidence files and immutable manifest remain authoritative. The v2
index is a bounded, deterministic, rebuildable cache. A crash between capture
finalization and index update cannot make a capture unavailable after an index
rebuild, and index corruption cannot redefine capture contents.

Python remains the only v1 manifest writer. W7 does not rewrite historical
captures or claim byte-exact v1 manifest serialization. New storage preserves
exact v1 stdout/stderr bytes and a v1-readable layout, while the native reader
continues to read Python v1 and pre-W7 native captures. Unknown optional fields
are tolerated; unknown required semantics fail closed.

## Status and durability semantics

Command, capture, presentation, and wrapper state remain separate:

- `completed` may carry `complete`, `truncated`, `degraded`, or
  `recovered-incomplete` capture state;
- degraded-but-usable evidence preserves the child status and has no wrapper
  error;
- an unusable required capture is `capture-failed` with a post-spawn capture
  error;
- recovery never invents an exit code, signal, timeout, or cancellation state.

A host-durable claim requires all of these steps to succeed in order:

1. stream, event-index, and immutable manifest/delta files are synced;
2. the partial capture directory is synced;
3. the partial entry is atomically renamed through pinned parent descriptors;
4. the destination capture parent is synced.
5. an immutable publication record binding the exact v2 sidecar digest is
   atomically written and the finalized capture directory is synced.

Failure before that boundary cannot be reported as complete host-durable
evidence. A capture visible after rename but lacking the publication record is
retained as uncommitted evidence: inspect and verify fail closed, recovery does
not promote it, and index rebuild records an issue instead of a complete
capture. The index is updated only after filesystem finalization and remains
rebuildable if that later update fails.

## Recovery, retention, and collection

Recovery operates only on descriptor-pinned regular artifacts, computes
observed hashes, and writes explicit recovered-incomplete evidence. It is
bounded, idempotent, never executes a command, and covers crashes before and
after manifest creation, rename, and index update.

Raw expiry is represented by a separate retention tombstone. The record pins
the original capture reference and immutable manifest digest, the prior capture
status, retention policy digest, expiry time and reason, and the fact that raw
retrieval is unavailable. Expiry never rewrites the immutable manifest and
never triggers an automatic rerun.

New ephemeral execution must create no named empty capture directory, so it
leaves zero W4-style tombstones. Legacy tombstones need special treatment:
there is no POSIX operation that conditionally removes a directory entry only
if it still names an already-open inode. A same-UID process can otherwise
replace the name between verification and `rmdir`. The collector therefore
removes a legacy empty directory only under exclusive spool ownership. If that
ownership cannot be established, or any identity check changes, collection
fails closed and retains the tombstone.

## Falsifying gates

The candidate is not complete until evidence covers:

- Python-v1 reads of new v2 captures and native reads of Python-v1 and pre-W7
  captures, with exact stdout/stderr bytes and hashes;
- crash injection at every durability step and before/after index update,
  followed by two idempotent recovery/rebuild passes;
- the shared command quota, injected `ENOSPC`/`EDQUOT`/`EIO`,
  write/sync/rename/publication/index failures, and
  continued concurrent pipe drainage without deadlock;
- descriptor-relative symlink and replacement attacks against spool roots,
  partial/final capture directories, every artifact, index data, and retention
  tombstones;
- one-byte tampering of streams, event index, manifest delta, and retention
  records, preserving expected and observed digests without silent rewrite;
- policy-driven dry-run and live collection, expired/unavailable retrieval with
  no rerun, concurrent retrieval/collection, exact bounds, and repeated GC;
- zero new ephemeral tombstones plus legacy replacement attacks both with and
  without exclusive spool ownership;
- schema examples and canonical bindings for complete, truncated,
  degraded-but-usable, and recovered-incomplete results;
- the complete Rust, Python, schema, conformance, package, and artifact gates.

## Intentional limits

W7 adds no central service, remote executor, remote replica backend, daemon,
workflow scheduling, retry or lifecycle authority, audit judgment, deployment,
PTY/live output, LLM projection, or raw-output publication. Long-term product
retention defaults remain deferred; W7 implements explicit local policy and
mechanics only.

Rollback remains:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

Rollback neither migrates nor rewrites capture, Sprintctl, ActionQ, audit, or
workflow state. Local one-version-back readers remain available for retained
evidence.

## Verification evidence

The candidate exercises immutable v2 sidecars, strict one-back readers,
raw-free deterministic index rebuild, exact external manifest commitments,
strict retention tombstones, and descriptor-relative recovery/collection.
Recovery hashes every present regular artifact without inventing command status. A
pre-manifest abandoned capture remains a one-back native recovery manifest
because the request/policy binding is not available after the interrupted
process; completed v2 pre-rename captures retain and promote their exact v2
sidecar. Index rebuild preserves verified expiry state and rejects an unsafe or
misbound retention record.

Local gates on 2026-08-12:

- Rust workspace/all-target tests: 84 engine, 7 CLI, and 1 contracts test,
  plus the presentation bench;
- injected `ENOSPC`, `EDQUOT`, `EIO`, manifest, sidecar, directory-sync,
  rename, parent-sync, publication-binding, and index-update failures pass
  without deadlock or a false completed-durability result;
- cargo-enabled Python/conformance suite: 286 passed, including native/Python
  cross-version reads and exact byte/hash verification;
- v2 schema examples: 22 passed;
- Ruff, strict Mypy over 37 source files, source/wheel build, AgentOps artifact
  validation, and `git diff --check`: passed.

The host does not expose the pinned Rust 1.85.1 toolchain. Rust verification
used the available Nix Rust 1.97.0 toolchain; the integration owner must repeat
the Rust gates with 1.85.1 before landing. Independent Terra rereview of this
correction remains pending.
