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
evidence at its adapter boundary. The opt-in `outctl run -- <argv>` CLI wrapper
now makes that boundary usable from a Codex or Claude command session. It does
**not** establish how much either harness already manages large command context
internally, because neither harness's native command-tool boundary is
intercepted. The expected first-pilot outcome is therefore directional: compare
what the harness exposes in a baseline appservice health-check workflow with
what it exposes through the opt-in wrapper, then judge whether the additional
bounded projection/retrieval path is materially useful.

## Environment observation

The local host has `codex`, `claude`, and `kubectl` executables available, but
no active Kubernetes context. No production or cluster access was attempted.
Consequently this record does not claim an appservice `kubectl` pilot result.

## Validated workstation pilot

An authorized paired Codex appservice health-check pilot completed on
`acb81f69c28f27cdde8bf1ed9cc074b290bcb74f` using policy digest
`sha256:e375fe09b170e70b4a9508a91322b7e2384a8389559ebe429dfb0520104cc773`.
Its metadata-only report validated locally and has SHA-256
`b3c9908e0c9485019c5cba751b54220427a7801a7410d8a5bbba7ce54250a942`.

| Measure | Baseline Codex | Opt-in outctl enforce |
|---|---:|---:|
| Exposed token estimate | 100,030 | 15,496 |
| Raw token estimate | n/a | 561,482 |
| Retrieved token estimate | n/a | 44 |
| Retrieval count | n/a | 1 |
| Wall time | 922 ms | 2,246 ms |
| Wrapper overhead | n/a | 1,324 ms |

The enforced projection reduced exposure by approximately 97.2% from captured
raw output and approximately 84.5% relative to the native exposed baseline.
One omitted marker was retrieved from the existing capture without a Kubernetes
rerun. Command and capture both completed successfully; digest verification
passed. The review decision was **continue**: native harness truncation omitted
middle context without a stable retrieval reference, while outctl made the loss
explicit and recovered evidence without re-execution.

The raw Kubernetes capture remains workstation-local. Only the report and a
metadata handoff were replicated to devbox as verified semi-ephemeral local
evidence; neither raw bytes nor session output were added to Git or a served
authority.

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
