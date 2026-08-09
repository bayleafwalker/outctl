# Workstation appservice pilot and review runbook

> Historical qualitative runbook. Do not use its broad-context workflow for a
> new live run. Current runs require the runner-owned identity boundary,
> genuine read-only RBAC, frozen expected facts for quality claims, and the
> ordered gates in `docs/ENABLEMENT_PLAN.md`.

## Preconditions

- Use the `main` revision containing `outctl run` and `outctl pilot-validate`.
- Use the explicit appservice kubeconfig and confirm the intended context and
  namespace. The current appservice context has broader permissions than the
  read-only corpus requires; do not run mutation commands.
- Use a fresh Codex or Claude session. Choose a representative `kubectl`
  health-check corpus, such as deployments, pods, events, and one deployment
  description. Never copy raw Kubernetes output into this report or Git.

## Paired run

1. Run the corpus normally in the selected harness. Record only approximate
   exposed bytes/tokens, wall time, failures, and a qualitative observation of
   the harness's own context/output management.
2. Run the same direct argv through the wrapper:

   ```bash
   uv run outctl run --mode enforce \
     --spool-root /tmp/outctl-appservice-pilot \
     --policy-ref <approved-policy> \
     --policy-digest <approved-sha256-digest> \
     -- kubectl --kubeconfig <appservice-kubeconfig> -n gatus get deployment,pod -o wide
   ```

3. If the projection omits a known marker, use `outctl slice`, `tail`, or
   `search` against the returned capture ID. Verify the original command ran
   once. Do not paste raw output into the report.

## Report and review

Create a local JSON report containing metrics and assessment only:

```json
{
  "pilot": {
    "harness": "codex",
    "command_class": "appservice-health-check",
    "policy_digest": "sha256:<digest>"
  },
  "baseline": {"exposed_tokens": 0},
  "enforce": {
    "raw_tokens": 0,
    "exposed_tokens": 0,
    "retrieved_tokens": 0,
    "retrieval_count": 0,
    "wall_time_ms": 0,
    "wrapper_overhead_ms": 0
  },
  "assessment": {
    "harness_native_context_management": "short qualitative assessment",
    "outctl_increment": "short qualitative assessment",
    "recommendation": "continue, adjust, or stop"
  }
}
```

Validate without revealing raw bodies:

```bash
uv run outctl pilot-validate /path/to/pilot-report.json
```

The review pass must confirm direct argv/no shell, a pinned policy digest,
separate command/capture status, one-execution retrieval, no raw output in the
report, and an explicit decision about whether the additional outctl boundary
is useful beyond native harness behavior.
