# Rollout and evaluation plan

> Current sequencing and study gates are canonical in
> `docs/ENABLEMENT_PLAN.md`. This document retains the original rollout-stage
> rationale; where the two differ, the canonical plan wins.

## Rollout principle

Prove subprocess correctness and measurable context savings before adding services, advanced profiles, or mandatory enforcement.

## Stage 0: contracts and fixture corpus

Deliver:

- schemas and policy parser;
- synthetic fixtures for large output, repetition, failures, non-UTF-8, mixed streams, secrets, and signals;
- direct-versus-wrapped conformance harness;
- baseline metrics from existing command sessions where available.

Gate:

- schemas validate;
- fixture expectations are reviewable before implementation;
- policy digest is stable and reproducible.

## Stage 1: local shadow capture

Run the wrapper in `shadow` mode where adapter capabilities permit:

- command executes through the capture path;
- existing unbounded output is still returned to the harness;
- projected output is generated but not substituted;
- raw/exposed estimates are recorded locally.

Gate:

- no material command semantic differences;
- no deadlocks;
- overhead is acceptable;
- capture recovery works after forced termination.

## Stage 2: bounded projection pilot

Enable `enforce` for one harness/runner and selected command classes.

Start with:

- test commands;
- build commands;
- recursive listings;
- log retrieval;
- large `git diff`.

Keep compact metadata commands full where they fit.

Gate:

- at least 50% output-token reduction for oversized results;
- omitted diagnostics can be retrieved without rerun;
- users do not routinely bypass due to missing evidence;
- raw capture and redaction tests pass.

## Stage 3: actionq/audit integration

- bind capture IDs to action attempts;
- publish compact completion and verification receipts;
- promote policy decision through kctl;
- add project-folder and handoff guidance.

Gate:

- retries produce distinct captures;
- audit evidence can verify hashes without carrying raw logs;
- local-only evidence is clearly distinguished from portable replicas.

## Stage 4: second harness and conformance

Integrate a second harness using the same execution/result schemas.

Gate:

- equivalent commands produce semantically equivalent envelopes;
- policy behavior does not depend on harness prompt compliance;
- adapter-specific differences are documented rather than hidden.

## Stage 5: hybrid registry and replicas

Only after local value is established:

- metadata registry;
- object/artifact backend;
- replica authorization;
- Vuoro reference resolution;
- workstation/devbox handoff test;
- GitOps policy distribution.

Gate:

- receiving host can retrieve and verify a replica by opaque reference;
- exact versus sanitized replica class is preserved;
- service outage does not remove local break-glass.

## Evaluation report

For each pilot session report:

- harness/model and context size;
- commands captured by profile;
- raw bytes/lines/estimated tokens;
- exposed bytes/lines/estimated tokens;
- follow-up slices and bytes/tokens;
- capture failures/truncations;
- bypasses and reasons;
- commands rerun because projection was insufficient;
- measured wrapper overhead;
- secret/redaction incidents;
- user/agent qualitative notes.

## Rollback

Set `OUTCTL_MODE=bypass`, reconcile configuration, and verify the direct runner path. Captures are passive artifacts and can be retained or garbage-collected. No sprintctl/actionq state migration is required.
