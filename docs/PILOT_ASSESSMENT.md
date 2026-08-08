# First pilot assessment

## Scope

This is a local, qualitative pre-pilot assessment for the intended Codex or
Claude appservice-health-check pilot. It contains no raw command or session
output. It is decision evidence, not an audit finding or a claim of production
integration.

## Objective evidence

- The local adapter supports bypass, shadow, and enforce modes, opaque capture
  references, bounded no-rerun retrieval, separate command/capture statuses,
  and compact safe receipts.
- The deterministic output-heavy pilot test records raw/exposed/retrieved token
  estimates, wall time, wrapper overhead, policy digest, execution count, and
  a qualitative assessment field. It proves a directionally smaller bounded
  projection while preserving a single capture execution.
- A representative long-output test exercises approximately 179k estimated raw
  tokens, retains capture within its configured quota, and proves at least a
  50% reduction for that local fixture. This is diagnostic evidence only, not a
  release threshold.
- A clean-clone installation, isolated import, CLI smoke check, full test
  suite, type check, lint, build, and verification-artifact validator have
  passed locally.

## Qualitative assessment

The local evidence establishes that `outctl` can bound and recover command
evidence at its adapter boundary. It does **not** establish how much Codex or
Claude already manages large command context internally, because neither
harness's native command-tool boundary is intercepted by the current library
adapter. The expected first-pilot outcome is therefore directional: compare
what the harness exposes in a baseline appservice health-check workflow with
what it exposes through an opt-in outctl boundary, then judge whether the
additional bounded projection/retrieval path is materially useful.

## Environment observation

The local host has `codex`, `claude`, and `kubectl` executables available, but
no active Kubernetes context. No production or cluster access was attempted.
Consequently this record does not claim an appservice `kubectl` pilot result.

## Required next evidence

Run the paired baseline and opt-in pilot in an authorized environment with an
appservice health-check command corpus drawn from representative Codex or
Claude session metadata. Record only:

- selected harness and adapter interception mechanism;
- command class and pinned policy digest;
- raw, exposed, and retrieved byte/token estimates;
- retrieval count, wall time, and wrapper overhead;
- failures, truncations, bypasses, and an explicit qualitative judgment of
  harness-native context management versus outctl's contribution.

Keep raw command and session output outside Git, sprintctl, kctl, auditctl, and
the report.
