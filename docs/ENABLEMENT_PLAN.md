# Canonical enablement plan

This document is the current operational sequence for enabling `outctl`.
`docs/IMPLEMENTATION_PLAN.md` remains the historical Phase 1 build order;
pilot handoffs describe implementation history, not current run authority.

No stage may be skipped. Evidence is metadata-only and can be evaluated with:

```bash
uv run outctl enablement /path/to/enablement-evidence.json
```

The checked-in starting shape is `config/enablement-evidence.example.json`.
Shared wire and evidence contracts plus ActionQ/audit/kctl mapping rules are in
`docs/CONTRACT_INTEGRATION.md`.

## Stage 0 — contracts and local gates

Require valid schemas, a stable policy digest, deterministic fixtures, and the
full repository gate. Phase 1 implementation is complete, but every candidate
enablement commit must rerun the gates in `AGENTS.md`.

## Stage 1 — model-free mechanism benchmark

Run deterministic capture, projection, retrieval, redaction, mixed-stream,
failure, verification, quota, recovery, signal, and cancellation cases without
a model or cluster:

```bash
umask 077
uv run outctl benchmark --spool-root /tmp/outctl-mechanism
```

The benchmark report is raw-free. It is supplemental to the normative
acceptance suite, not a replacement for it.

## Stage 2 — runner-owned execution identity

Use `outctl.kubernetes.run_kubernetes_read` or an equivalent native harness
tool. The caller supplies logical argument vectors. The runner validates them,
injects the executable, kubeconfig, and context, launches direct argv, and
emits a binding over executable, kubeconfig, context, API server, and argv.

Treatment and control receipts must carry the same
`identity_binding_sha256`. Suppress comparison when a receipt is absent or
different. A stock shell hook is not an identity or security boundary. Every
live Kubernetes run requires genuine read-only RBAC.

## Stage 3 — selected shadow operation

Enable `shadow` only for selected harnesses and high-volume command classes.
Return the ordinary result while capturing and projecting privately. Record
semantic comparisons, overhead, recovery, deadlocks, capture failures, and
bypasses. Do not proceed until direct and shadow behavior are equivalent and
rollback has been exercised.

## Stage 4 — frozen controlled efficacy study

Use replayable or seeded scenarios with expected facts frozen before model
runs. Start with six scenario classes and three repetitions (18 matched pairs),
then revise final sample size only from a separate pilot variance estimate.

Co-primary outcomes are diagnostic quality non-inferiority, zero additional
critical/high misses, model-visible command output, and uncached-read input.
All protocol-valid pairs stay in the dataset when diagnoses disagree. Report
each pair and paired effects first; pooled totals are secondary.

Commissioning, adaptively inspected, identity-invalid, broad-authority, and
unknown-denominator runs are not confirmatory evidence.

## Stage 5 — real UX pilot

Run separately from the controlled efficacy study. Measure adoption, logical
command count, reruns avoided, retrieval contribution to cited findings,
bypass reasons, and multi-turn context accumulation. Require `evidence_refs`
for findings and checks. Retrieval should answer a specific unresolved
question and batch related literals with `search-many`.

## Stage 6 — selected enforcement

Enable `enforce` for approved output-heavy command classes only after Stages
0–5 pass. Keep small outputs full when they fit. Require at least 50% visible
output reduction for oversized results, preserved quality, verified redaction,
acceptable bypass pressure, and tested rollback.

The opt-in CLI helper remains transitional. Product enforcement belongs in a
native runner/harness command boundary.

## Stage 7 — authority integration and second harness

This stage requires explicit cross-repository authority. Bind captures to
action attempts, publish compact verification receipts through owning APIs,
promote policy intent through kctl, and integrate a second harness against the
same schemas. Never write raw output into actionq, auditctl, kctl, sprintctl,
Git, or project-folder metadata.

## Stage 8 — hybrid portability

Only after local value and two-harness conformance are established, add a
metadata registry, authorized artifact backend, opaque reference resolution,
replica verification, and GitOps policy distribution. Preserve `raw-exact`,
`raw-sanitized`, `manifest-only`, and `projection-only` classes. A service
outage must not remove local retrieval or bypass.

## Deferred features

PTY capture, compression, sparse indexes, live bounded progress, exact
tokenizers, semantic derived summaries, and remote-only operation require
separate measured need and design approval.

## Rollback

At any enabled local stage:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

Verify the previous direct runner path. Captures remain passive evidence that
can be inspected or garbage-collected. No action, sprint, audit, or policy
state migration is required.
