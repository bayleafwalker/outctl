# Outctl W0 baseline

This directory is the frozen, raw-free W0 evidence package. It contains
metadata and references only; the exact capture spool remains host-local at
the path recorded in `host-local-references.json` and is not portable.

- `repository-state.json` records the clean baseline commit and applicable
  risk surfaces.
- `baseline-report.json` records the model-free mechanism benchmark and its
  gates.
- `startup-syscalls.json` records fresh-process startup samples, including
  syscall counts and seconds parsed from `strace -c`, plus wall-time p50/p95/p99.
- `golden-metadata.json` freezes the raw-free benchmark metadata and policy
  digest.
- `host-local-references.json` records manifest hashes and local capture paths.
- `artifact-audit.json` maps every untracked W0 artifact to the exact roadmap
  authorization.
- `gate-results.json` records normative gate outcomes without embedding
  command output.

The baseline report also records empty and one-line command profiles plus a
1,000-command linear projection. The projection explicitly records that only
one representative command was executed.

The governing roadmap is intentionally not materialized into this
`origin/main`-based worktree. Its exact provenance is commit
`1c8d6aeaa6f3526c50cb3626d6d7e301930f2b7d`; no roadmap content was merged or
cherry-picked.
