# Devbox implementation handoff — concurrent Terra A/B pilot

> Historical app-server-first implementation handoff. It is retained for
> provenance and does not define the current enablement path or authorize a
> live run. See `docs/ENABLEMENT_PLAN.md`.

## Purpose and scope

Continue the local, read-only concurrent A/B pilot implementation. This is
implementation and offline/canary verification work only. Do **not** push,
open a PR, run a live cluster pilot, change RBAC, or publish any captures,
projections, transcripts, or report bodies.

The supplemental command policy belongs only in the pilot's Codex app-server
client. It must not become an `outctl` daemon, a general command router, or a
new command-execution surface. `outctl` continues to own capture/projection/
retrieval mechanics only.

## Starting revision

Workstation source revision: `cede1c1` (`Allow only frozen corpus app-server
commands`), on local `main`, based on `origin/main` `fe6a7eb`.

The worktree was clean when this handoff was prepared. These local commits are
not pushed and must be transferred deliberately to the isolated devbox-vm
clone (for example through a verified Git bundle). Do not assume a matching
`/projects/dev/outctl` path means matching files across hosts.

Relevant local commits, oldest first:

```text
b9b82d6 Handle denied kubectl auth checks
0beb6d2 Create pilot session directories safely
b806d29 Keep Codex diagnostics out of pilot telemetry
dc1c9e8 Add app-server token telemetry primitives
eed80a4 Run pilot sessions through app-server telemetry
6e2db1f Derive pilot retrieval proof from spool evidence
acfed6b Preflight app-server token telemetry
9c7b1a0 Pin pilot corpus routes in app-server sessions
52a8945 Use app-server thread sandbox mode
cede1c1 Allow only frozen corpus app-server commands
```

## Current state

`CommandApprovalPolicy` and the JSON-RPC responder exist in
`src/outctl/pilot.py`. They accept canonical exact argv spellings of four
frozen read-only corpus commands once per session; A wraps them in `outctl run
--mode enforce`, and can perform one bounded `outctl tail` after a manifest
exists. The responder denies file-change and all other permission requests.

The implementation is not yet sufficient for a trustworthy pilot. Treat the
following as blockers, not optional refinement:

1. Configure the pinned app-server to actually issue granular command
   approvals. `approvalPolicy: "never"` cannot be used if it suppresses the
   callback. Before changing semantics, run a no-cluster canary against the
   generated schema for the installed Codex version and prove that all target
   routes emit `item/commandExecution/requestApproval`.
2. Remove any broad static A rule that permits arbitrary `outctl run`; the
   app-server gate must be the authority for exact trailing argv. Make A's
   literal spool path consistent across guidance, environment, and gate.
3. Separate approval from execution. Bind unique `itemId`s to the approved
   canonical argv; require a matching `item/completed` event with successful
   status/exit for all four commands. Ignore `aggregatedOutput` and all raw
   tool bodies immediately.
4. Bind A's one retrieval to the capture produced by corpus command four
   (oversized pod inventory), not merely any existing manifest. Require four
   successful captures, exactly one retrieval, and no fifth Kubernetes event.
5. Give B equivalent completion metadata (without inventing retrieval) so the
   report can prove four direct, successful corpus commands and zero outctl
   retrievals.
6. Add a bounded structured output schema to `turn/start`; retain only
   validated health conclusion/evidence/retrieval fields. Compare the two
   conclusions without retaining model or tool bodies.
7. Record real wall time and bounded barrier start skew. Reject a dirty
   checkout and verify the invoked `outctl` maps to the pinned commit.
8. Make preflight test the exact corpus RBAC: context validation; `get nodes`;
   cluster-wide `list pods`; required gatus reads; and denial of all relevant
   mutations. A read-only scoped kubeconfig is mandatory.
9. Repair `_guided_evidence`: read each capture's correct manifest fields;
   report per-capture raw/exposed/retrieved metadata; verify hashes; and never
   emit raw/projection bodies.
10. Make both old JSONL and app-server accounting consistent: cached input is
    a subset of input. `model_context_memory = input_tokens`; aggregate cache
    is `cache_read + cache_write`. Report cost as `null` plus
    `provider_unavailable`; do not estimate pricing.

## Required policy contract

The app-server gate may accept only these one-shot, canonical requests, after
matching session, thread, turn, cwd, and an unused item ID:

- A: each of the four literal corpus `kubectl` argv vectors, wrapped exactly
  as `outctl run --mode enforce --spool-root <absolute-session-spool> -- ...`.
- B: the same four literal `kubectl` argv vectors directly.
- A only: one literal `outctl tail --spool-root <absolute-session-spool>
  <capture-from-corpus-index-3> stdout --lines 20` after that capture is
  complete and hash-verifiable.

Deny shell grammar, aliases, absolute-path substitutions, duplicate commands,
extra args, mutations, dynamic tools, file changes, permission/network policy
amendments, session-wide grants, malformed/mixed-session requests, and all
other server-initiated requests. Do not introduce a shell or retain tool
output.

If the no-cluster canary proves command approval callbacks cannot be forced for
all routes in the pinned Codex version, stop. Describe the current gate as
post-validation only; do not run the live A/B. The only acceptable fallback to
consider is a client-owned command tool/executor, which needs separate design
approval because it changes the harness boundary.

## Required tests and gates

Add focused fixtures/tests for protocol schema drift; approval request and
completion correlation; exact argv; one-shot state; wrong thread/turn/item;
shell/mutation/file/permission denial; oversized-capture retrieval binding;
missing/failed completion; B completion evidence; structured conclusion
validation; token accounting; wall-time skew; dirty/stale executable;
preflight RBAC; and raw-free report enforcement.

Run, in order:

```bash
uv sync --all-extras --dev
uv run pytest tests/test_pilot.py
uv run pytest
uv run ruff check .
uv run mypy src
uv build
python /projects/dev/agentops/templates/dispatch/scripts/validate_verification_artifacts.py --root .
uv run outctl pilot smoke
```

The devbox-vm may lack cluster reach and should perform only offline/no-cluster
canaries. A live pilot remains a workstation or legacy-pod action using a fresh
short-lived read-only service-account kubeconfig.

## Handoff classification

Source host: workstation. Source path: `/projects/dev/outctl`.

Classification: host-persistent Git worktree; no raw capture/transcript is
part of this handoff. Durable references: none. Retention: retain the Git
history until this pilot work is integrated or intentionally superseded; the
temporary transport bundle may be discarded after both replicas verify it.

Verified replica: devbox-vm `/tmp/outctl-devbox-pilot-implementation`, checked
out from branch `devbox-pilot-implementation`. It was created at commit
`706046780f1c02474f254d583d86c8ac83844379` after verifying transfer bundle
SHA-256 `825d9d5ed31a7bcf48653f0bc4a23bf215c0163bd2a62c9a897cf55747be520e`,
then fast-forwarded to `cd0620ae1f5c8aa86e114f512132c8fbd4c19eed` after
verifying follow-up bundle SHA-256
`06025fa48259735f021ba18f907dded688e5acf3bb4f0c600605f9340c96d8a4`. This
replica is host-persistent but not durable-authoritative; it remains
unpublished Git state until a separately authorized review and push.
