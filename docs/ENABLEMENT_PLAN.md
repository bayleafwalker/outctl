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

Freeze overhead acceptance before collecting a gate observation. Measure at
least five paired repetitions of the same direct-argv request in alternating
order and compare medians. For a direct median of at least 1,000 ms, the shadow
median may regress by less than 5%. For a direct median below 1,000 ms, the
shadow median may add at most 100 ms. Report milliseconds and parts per million
in either stratum. Earlier observations are commissioning evidence only and
must be rerun; they cannot pass Stage 3 retroactively.

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

Files under `examples/` are illustrative and never launch authority. Launch
requires checked-in scenario manifests and expected-fact files whose canonical
SHA-256 digests match the frozen protocol. Placeholder digests or a repository
commit other than the candidate study commit invalidate the protocol.

## Stage 5 — real UX pilot

Run separately from the controlled efficacy study. Measure adoption, logical
command count, reruns avoided, retrieval contribution to cited findings,
bypass reasons, and multi-turn context accumulation. The first long-horizon
workflow should place a 30–100 KB result near the beginning, require 15–30
later investigation/tool cycles, freeze the exact command order in both arms,
and record context-size proxies per inference when the harness exposes them.
Require `evidence_refs` for findings and checks. Retrieval should answer a
specific unresolved question and batch related literals with `search-many`.
The checked-in Codex scaffold is
`acceptance/codex_appservice_ab/long-horizon-workflow.json`; it remains
non-evidence until a scoped read-only live run is authorized.

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
tokenizers, and remote-only operation require separate measured need and
design approval. Semantic derived summaries are now a scoped exception:
docs/INTERACTION_ERGONOMICS.md defines the separate ergonomics hypothesis,
and the first adapter is limited to complete Kubernetes Pod health tables.

## Rollback

At any enabled local stage:

```text
OUTCTL_ENABLED=0
OUTCTL_MODE=bypass
```

Verify the previous direct runner path. Captures remain passive evidence that
can be inspected or garbage-collected. No action, sprint, audit, or policy
state migration is required.
