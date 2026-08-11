# W3 Rust process and capture handoff

**Backlog:** `#2135`
**Base:** `origin/main` at `1d3cdf179a70ac5c4819b742d9749a8ac336ade5`
**Scope:** Rust process/capture parity and v1-compatible reads only

## Delivered boundary

The opt-in `outctl-native` path now implements Linux non-PTY direct-argv
execution, isolated process groups, timeout and caller-cancellation handling,
concurrent stdout/stderr drainage, one shared retention quota capped by the
advertised 268,435,456-byte engine limit, atomic local finalization, partial
recovery, bounded retrieval, digest verification, and
machine-readable phase timings.

Spool traversal, artifact reads/writes, recovery, and finalization are anchored
to pinned directory descriptors. Child directories and regular files use
descriptor-relative no-follow opens, and the final move uses `renameat` between
the pinned partial and capture parents. Pathnames returned in results are
display metadata only and are never reused as storage authority.

Python remains the default compatibility engine. `OUTCTL_ENGINE=rust-native`
is explicit and fails closed when the binary is absent; either
`OUTCTL_ENABLED=0` or `OUTCTL_MODE=bypass` selects the Python rollback
boundary. No capture migration is performed.

The Rust engine does **not** claim to be the v1 manifest writer. Native
captures identify their schema as `vuoro.outctl.capture-native/w3` and retain
the frozen compatibility claims:

- `v1_reader=readable`;
- `v1_writer=python-reference-only`;
- exact v1 stdout/stderr stream bytes are preserved;
- v1 manifest byte equality is false;
- unknown fields are ignored.

This permits the existing Python inspect/verify reader to consume native
captures and the native reader to consume Python captures without violating
W1 gate G5.

## Falsifying gates

The W3 test layer covers:

- exact Python/Rust stdout and stderr byte counts and SHA-256 digests;
- zero, nonzero, signalled, and timed-out child outcomes;
- literal argv and no implicit shell expansion;
- mixed-stream drainage after shared-quota exhaustion;
- caller cancellation and timeout cleanup of descendant processes;
- a bounded post-exit drain grace for inherited pipes, followed by process-
  group cleanup so a background descendant cannot hang or outlive capture;
- Python-to-Rust and Rust-to-Python inspection and digest verification;
- workspace-bound authorization across inspect, slice, tail, search, and
  verification reads;
- incomplete recovery without command execution;
- mode-0700 spool/capture directories and mode-0600 evidence files;
- traversal/symlink denial and tamper detection;
- adversarial root/capture replacement after descriptor acquisition, including
  finalization that remains between the original pinned parent directories;
- acceptance at exactly 268,435,456 retained bytes of configured quota and
  pre-spool rejection at 268,435,457;
- bounded resident memory while draining output far beyond the capture quota;
- explicit engine selection, rollback, and native command/finalization/drain
  timings.

The differential runner is test-only because it executes deterministic argv
twice. It must never be used for stateful production commands.

## Verification

Run the repository gates with the pinned Rust toolchain available:

```text
uv sync --all-extras --dev
uv build
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
uv run pytest
uv run ruff check .
uv run mypy src
python scripts/check_package.py
python /projects/dev/agentops/templates/dispatch/scripts/validate_verification_artifacts.py --root .
```

Observed on the isolated candidate:

- pinned Rust `1.85.1`: format, check, clippy, and all workspace tests passed;
- native workspace tests: 17 unit tests passed across CLI, contracts, and
  engine crates, plus doc tests;
- Python full suite: `220 passed`;
- W3 native integration suite: `14 passed`;
- Ruff and Mypy: passed;
- wheel and source distribution build: passed;
- exact wheel membership/package checks: passed;
- AgentOps verification-artifact validator: passed with no verification
  artifacts present.

The candidate contains no raw command output or capture spool. Local test
spools remain ignored and host-local.

`SHA256SUMS` is an ungoverned historical seed: repository history contains no
validator or CI consumer, and the file has not tracked later repository
changes. W3 leaves it untouched rather than inventing a new inventory format
or authority.

## Intentional W3 limits

W3 does not add explicit shell, stdin, PTY, projection/presentation, policy
compilation, secret registration, v2 storage, remote execution, replication,
workflow state, action lifecycle, audit judgment, or deployment behavior.
Those remain in later roadmap waves or their owning repositories.

Rollback remains:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

Do not start W4 from this candidate until W3 review and all gates are green.
