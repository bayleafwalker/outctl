# W0 baseline report

W0 froze measurement and repository evidence only. No `src/` behavior,
Cargo, adapter integration, Sprintctl/ActionQ state, production access, or
raw-output publication was added.

The baseline was commit `156e8e10af041ac5b35c8d5dac0e2adbcbcec4ab` on
`codex/outctl-2132`, with a clean worktree and `origin/main` at the same
revision. The governing roadmap was read exactly from commit
`1c8d6aeaa6f3526c50cb3626d6d7e301930f2b7d`; it was not merged or
cherry-picked into this worktree.

The model-free benchmark ran four cases once at scale 20,000. Captures were
verified and remain local-only under the path in
[`host-local-references.json`](../verification/w0/host-local-references.json).

Fresh-process startup was sampled seven times for direct-source, installed
wheel, and `uv run` paths. Each report includes p50, p95, and p99. Syscall
counts and elapsed syscall seconds were collected with `strace -c`; the parser
uses the summary's `seconds` column and excludes the `total` row. The results
are preserved in [`startup-syscalls.json`](../verification/w0/startup-syscalls.json). Empty and
one-line command profiles and a 1,000-command linear projection are in
[`baseline-report.json`](../verification/w0/baseline-report.json).

The frozen raw-free package is [`verification/w0`](../verification/w0/).
Raw capture bytes, command output, and syscall traces are not in Git.

## Gate results

- Targeted W0 tests: `64 passed, 1 skipped`.
- Full suite through the cached isolated toolchain: `175 passed`.
- `uv run ruff check .` passed.
- `uv run mypy src` passed (`23 source files`).
- AgentOps verification-artifact validator: passed; the repository currently
  has no AgentOps context/result artifacts.
- Normative `uv sync --all-extras --dev` and `uv build` passed from the cached
  toolchain. The wheel SHA-256 is recorded in the baseline report and was used
  for the installed-Python benchmark in a fresh isolated environment.
