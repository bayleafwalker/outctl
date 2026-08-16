# Discovery decision: kill the outctl product thesis

**Decision date:** 2026-08-16  
**Status:** killed as a product direction; repository retained as a frozen
discovery artifact  
**Replacement direction:** native harness execution with OpenTelemetry,
Langfuse or Phoenix, and object storage for large payloads

## Decision

Stop product development on `outctl`. Do not delete the implementation or the
recorded experiments yet: they are useful controls, historical evidence, and a
record of the problem that led to the replacement architecture. New work must
not extend the execution router, command projection system, custom observation
store, or agent-facing retrieval surface as a product roadmap.

The only surviving hypothesis is one bounded replacement-first spike:

> Can a thin adapter capture a complete tool result before a coding-agent
> harness truncates or discards it, attach temporal identity and provenance,
> store the bytes immutably, and expose a standard observability reference?

That hypothesis is an integration question, not a reason to continue building
`outctl`. The preferred implementation is an adapter at each harness boundary
feeding standard OTel and an existing backend.

## Evidence that closed the original thesis

### Native Code Mode was observed

The Luna app-server commissioning capture demonstrated the execution topology
that motivated the original context-reduction design:

```text
custom_tool_call(name=exec)
  generated JavaScript
    Promise.all([
      tools.exec_command(...),
      tools.exec_command(...)
    ])
  text(reduced_result)
        |
        +-- commandExecution
        +-- commandExecution
        +-- custom_tool_call_output (reduced result)

custom_tool_call(name=exec)
  generated JavaScript
    tools.exec_command(...)  # repair call
        |
        +-- commandExecution
        +-- custom_tool_call_output
```

This is observed Codex Code Mode transport behavior. It is not evidence that
the Codex app-server exposed the public Responses API PTC item contract
verbatim. The distinction remains important: transport evidence,
Responses-style PTC semantics, and program behavior are separate evidence
domains.

The complete commissioning archive is preserved at
[`/tmp/outctl-codex-luna-appserver-20260816.tar.gz`](file:///tmp/outctl-codex-luna-appserver-20260816.tar.gz)
with SHA-256:

```text
e16384161d2a03ebe18e832fd1b6aac7533ef4b5e038d421065ea687f1ce557d
```

### Native Code Mode beat the old comparison direction

The matched commissioning pair compared the old outctl-guided path with a
native path using the same Luna workload and read-only scope. Both arms found
the same substantive problems and returned `overall_status=degraded`:

- the same two Pending Nextcloud cron pods;
- the same Tdarr Error/OOMKilled population, including the same OOMKilled pod.

Quality non-inferiority was **not established** because there was no frozen
quality oracle or known denominator. The reported disagreement was primarily a
classification difference (`high` versus `warning`), not evidence that Arm A
missed a substantive finding. This is commissioning evidence, not a
confirmatory efficacy result.

The economics still close the old product direction. The recorded totals were:

| Metric | Outctl arm A | Native arm B | A relative to B |
| --- | ---: | ---: | ---: |
| Command-output bytes | 61,849 | 52,335 | +18.2% |
| Uncached input tokens | 36,787 | 31,432 | +17.0% |
| Total input tokens | relative change only | relative change only | -20.8% |
| Cached input tokens | — | — | -29.8% |
| Output tokens | 2,682 | 1,529 | +75.4% |
| Reasoning tokens | 494 | 175 | +182.3% |
| Duration | 61.5 s | 39.2 s | +56.8% |

The outctl arm also performed an additional roughly 2.1 KB tail retrieval.
Its dominant operation was `kubectl get pods -A -o wide`; the captured raw
stdout was about 53 KB and the bounded projection was effectively the same
size. The path therefore did not demonstrate a useful reduction against
native Code Mode. One pair cannot estimate effect size, but it is sufficient to
stop treating context compression as the strategic product thesis.

The corrected A/B archive is preserved at
[`/tmp/outctl-native-vs-outctl-luna-20260816.tar.gz`](file:///tmp/outctl-native-vs-outctl-luna-20260816.tar.gz)
with SHA-256:

```text
204ecb04590812c35929b8c2136c499866a5916f31533d3334652353a155a460
```

The pre-pivot committed baseline descriptor is preserved at
[`/tmp/outctl-pre-pivot-baseline-20260816.json`](file:///tmp/outctl-pre-pivot-baseline-20260816.json).

## What replaces it

The replacement architecture is intentionally small:

```text
Codex app-server / Claude PostToolUse / OpenCode
                    |
                    v
             thin capture adapter
                 /         \
                v           v
       MinIO / S3 blobs     OTLP spans/events
       raw bytes + sha256   Langfuse or Phoenix
                \           /
                 v         v
             temporal trace/session identity
                    |
                    v
               later retrieval
```

Use the OpenTelemetry GenAI conventions where they apply, including the
`execute_tool` operation, tool call identity, arguments, and result metadata.
Do not invent a second observation schema unless the integration proves that a
standard field cannot carry the required reference.

Large stdout/stderr should not be copied into span attributes by default. The
capture adapter should emit an artifact reference containing at least:

```json
{
  "sha256": "...",
  "bytes": 538404,
  "media_type": "text/plain",
  "uri": "s3://agent-evidence/sha256/..."
}
```

The adapter may apply an explicit redaction policy before storage, but it must
make the policy and resulting digest observable. It must not schedule commands,
choose actions, own agent state, provide a custom UI, or become a second trace
backend.

The relevant ecosystem references are:

- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
- [Langfuse observability](https://langfuse.com/docs/observability/overview)
- [Phoenix self-hosting](https://arize.com/docs/phoenix/self-hosting)
- [AgentOps spans](https://docs.agentops.ai/v2/concepts/spans)

These systems already cover most of the proposed durable-trace product:
sessions, spans, tool inputs/outputs, search, APIs, UI, retention, and agent
access. The remaining uncertainty is capture timing at the harness boundary.

## One allowed replacement-first spike

Run this only as a bounded triage exercise. It is not a continuation of the
outctl roadmap.

1. Start Langfuse or Phoenix and an S3-compatible store such as MinIO.
2. Capture one read-only Codex app-server session and one Claude
   `PostToolUse` result through thin adapters.
3. Emit an OTel tool span with a trace/session ID, tool call ID, result status,
   duration, byte count, digest, and object-store reference.
4. End the session and remove its conversational history, or simulate context
   compaction.
5. Start a successor agent with only the task state and trace/session ID.
6. Ask for an exact historical fact, such as which pod was OOMKilled, its
   restart count, its node, and the output that established the fact.
7. Measure correctness, evidence fidelity, rerun count, input tokens,
   retrieval bytes, latency, and stale/wrong-evidence retrieval.

The hypothesis passes only if the successor can locate and retrieve the
immutable historical result without rerunning Kubernetes. It fails if the
backend cannot preserve or address the full result, or if the adapters require
substantial outctl-specific execution, storage, query, or session semantics.

If the spike passes, keep the adapters with the harness/runtime integrations
and use the observability platform as the product surface. If it fails, record
the exact missing capability before considering a tiny portable artifact helper.
Do not reopen the old compression thesis on the basis of a failed integration.

## Frozen repository scope

### Retained as historical controls

- `outctl run` and the direct command-capture adapter;
- bounded projection and retrieval implementations;
- raw-free observation records and schemas;
- Codex app-server and trace-handler commissioning tools;
- the historical A/B runner and its archives;
- study, scenario, and acceptance harness code.

These are preserved for reproducibility, regression comparison, and discovery.
They are not recommended as a new runtime path.

### Killed as strategic work

- execution routing and command scheduling;
- kubectl-specific compression or projection policy;
- generic projection whose primary goal is model-context savings;
- orchestration and model guidance for choosing outctl;
- a custom trace, session, metrics, query, or UI backend;
- broad agent-facing durable-observation commands;
- automatic cost or token-economics claims;
- additional native-Code-Mode versus outctl A/B runs.

Normal harnesses should execute and reduce work using their native capabilities.
The observability stack should retain what is consequential. This repository
should receive only maintenance fixes required to keep its historical fixtures
readable or to document the decision.

## Ownership and project status

`outctl` has been removed from the Vuoro project membership list. The repository
is now a standalone archival experiment rather than an active Vuoro subsystem.
The new OTel/Langfuse/Phoenix path belongs at the native runtime or harness
integration boundary and to the team operating the observability deployment.
No new cross-repository ownership is inferred by this note.

The authoritative removal is in `members/agentops/project.toml`, with the
boundary note in `members/agentops/.project/sources/10-ecosystem-boundaries.md`.
This shared-read project instance could not regenerate its derived root
`AGENTS.md`/context bundle: the materializer rejects the existing managed `.git`
marker, and several referenced member worktrees are read-only. A later normal
agentops render/materialize operation should refresh those derived files from
the committed canonical binding; the stale snapshot is not a second source of
truth.

The decision is successful even if no outctl code survives. The useful outcome
is identifying the capture boundary and delegating storage, tracing, search,
sessions, and retrieval to standard infrastructure.
