# ADR-0001: Place bounded command-output handling at the runner/harness boundary

**Status:** Proposed  
**Date:** 2026-08-03

## Context

Long-lived model sessions can lose a material fraction of context to command output. Manual `head`, `tail`, and `grep` save tokens but destroy evidence before it receives a stable identity and can force expensive or stateful reruns.

The Vuoro ecosystem already separates responsibility:

- sprintctl owns work state and acceptance intent;
- actionq owns action lifecycle;
- runners and harnesses execute;
- auditctl records evidence and findings;
- kctl stores curated knowledge and decisions;
- Vuoro coordinates and discovers capabilities.

The output feature must fit those boundaries instead of becoming a new execution authority.

## Decision

Implement command-output capture and deterministic projection immediately around subprocess execution in the runner/harness adapter.

The component will:

- capture stdout/stderr to host-local evidence;
- return a bounded projection to the model;
- provide stable retrieval without rerun;
- emit compact receipts;
- remain bypassable.

It will not schedule, retry, or interpret work completion.

## Consequences

### Positive

- subprocess semantics and stream draining can be tested centrally;
- all harnesses can share one result ABI;
- loss is explicit and recoverable;
- action and audit systems receive compact evidence references;
- local break-glass remains possible;
- later remote storage does not dictate execution architecture.

### Negative

- each harness needs a real adapter to achieve enforcement;
- stock harnesses that retain an unrestricted shell tool may bypass the wrapper;
- raw output introduces local storage, retention, and secret-handling obligations;
- deterministic profiles require test fixtures to avoid hiding diagnostics.

## Alternatives rejected

### Prompt-only guidance

Telling agents to pipe through `head`, `tail`, or `grep` is useful hygiene but not an architecture. It is voluntary, lossy, unmeasured, and cannot recover omitted ranges.

### Central Vuoro execution service

This would merge coordination with command lifecycle, weaken local break-glass, and create an unnecessary cluster dependency. It also duplicates actionq/runner responsibility.

### Store complete logs in auditctl or kctl

Both are wrong authorities. Auditctl should retain compact immutable receipts and findings; kctl should retain curated knowledge and decisions. Bulk logs would degrade both.

### LLM summarization before capture

A semantic summary is nondeterministic, costs more model usage, may omit the decisive line, and is not raw evidence. It may be added later as a derived artifact only.

### Shell aliases alone

Aliases do not apply consistently to noninteractive shells, direct argv execution, or harness-native tools. They are acceptable for experiments, not enforcement.

## Validation

The decision is validated when one harness can:

1. run real implementation work through the wrapper;
2. reduce oversized command output by at least 50%;
3. retrieve omitted diagnostics without rerunning;
4. preserve exit/cancellation semantics;
5. bypass the wrapper cleanly.
