# W1 #2133 continuation handoff

**Candidate state:** corrected after Terra NO-GO, uncommitted, not pushed  
**Baseline:** `9099640f0523a3cdcb2c709e6d0e0e7799a460e6`  
**Roadmap provenance:** `1c8d6aeaa6f3526c50cb3626d6d7e301930f2b7d`

## Delivered in this candidate

- accepted ADR-0002 through ADR-0005 and the W0-W8 roadmap/decision gates;
- v2 `RunRequest`, `PolicySnapshot`, `RunResult`, `EngineCapabilities`, and
  additive capture-manifest delta schemas;
- trusted/restricted request examples and explicit bypass/unsupported results;
- raw-free canonical digest vectors and a cross-engine comparison oracle;
- wrapper error codes with command/capture status separation;
- dispatch scope, risk surfaces, and protected paths updated for the migration;
- tests proving schema validity, policy non-authorization, compatibility claims,
  explicit outcomes, and digest stability.
- Terra gate correction: each W1 decision now freezes a selected option,
  invariant, falsifying verification, and bypass rollback in
  [`DECISION_GATES.md`](DECISION_GATES.md).
- v2 schemas now reject contradictory direct/shell, trust/disclosure,
  commitment/durability, secret-channel, wrapper-phase, and outcome/status
  combinations. Requests/results bind snapshot ID, reference, and digest;
  capture deltas now carry and validate the same frozen policy triple, while
  retaining the Python-only v1 writer stance.
- the wheel force-includes every `examples/v2` asset and the raw-free
  conformance digest, matrix, README, and comparator; an exact membership test
  checks the built wheel.
- `conformance/v2/comparator.py` machine-checks exact, semantic,
  intentional-difference, and negative mismatch cases; policy binding tests
  exercise request, result, and capture-delta documents against the snapshot.

## Verification

- targeted: `17 passed` (`tests/test_v2_contracts.py` after the package build);
- full: `191 passed`;
- `uv run ruff check .`: passed;
- `uv run mypy src`: passed;
- `uv sync --all-extras --dev`: passed;
- `uv build`: passed;
- exact wheel membership: passed;
- AgentOps verification-artifact validator: passed; no verification artifacts
  were found.

The final scope audit found no Cargo workspace, Rust source, runtime, deploy,
commit, push, or Sprintctl mutation in this correction. The only behavior
contracted for a future engine is documented/schema-level W1 behavior; the
Python v1 implementation remains unchanged.

No raw capture bytes, secrets,
Sprintctl/ActionQ/audit state, deployment, or external authority were changed.

## Next continuation

W2 may add the Cargo workspace and Python control/extension layout only after a
reviewer accepts these contracts and digest vectors. W2 must not execute
commands in Rust. W3 owns process/capture parity. Do not begin W4-W8 work in
this candidate.

The live project-wide Sprintctl backlog could not be read because the configured
backend only exposes the local four-item historical sprint; local item `#2133`
was not found. This handoff intentionally does not claim, edit, or reconcile
Sprintctl state. The branch/worktree claim and roadmap commit are the available
scope evidence.

Rollback remains:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

The Python v1 engine and v1 capture readers remain unchanged and runnable.
