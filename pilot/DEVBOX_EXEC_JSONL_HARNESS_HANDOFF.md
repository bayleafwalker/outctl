# Devbox handoff — `codex exec --json` A/B harness

## Objective

Implement and review an experiment-local replacement for the current
app-server-first pilot transport. The new harness must run matched, concurrent
`gpt-5.6-terra` sessions with `codex exec --ephemeral --json` as the
authoritative token-usage ledger, while a reviewed `PreToolUse` hook enforces
the experiment's read-only command policy.

This is an evaluation harness under `acceptance/codex_appservice_ab/`, not a
new outctl execution subsystem. Do not modify core capture semantics, add a
daemon, create a generic command router, or change appservice/cluster state.

## Inputs and verified assessment

The workstation-local reference package is:

```text
/home/bayleaf/Downloads/outctl-codex-appservice-ab.zip
```

It is source material, not an approved patch. Review and integrate deliberately
in a new branch; do not copy it blindly into the repository.

Short workstation assessment on 2026-08-08 established:

- Codex CLI `0.146.1` emitted a final `turn.completed.usage` JSONL object with
  `input_tokens`, `cached_input_tokens`, `cache_write_input_tokens`,
  `output_tokens`, and `reasoning_output_tokens` for an isolated no-tool
  `gpt-5.6-terra` probe.
- `reasoning_output_tokens` is a subset of output and must not be charged a
  second time.
- Codex `PreToolUse` supports Bash denial before execution. Treat hooks as
  guardrails only; Kubernetes RBAC remains the enforcement boundary.
- The supplied package's test suite could not import `jsonschema` in the
  current outctl environment. Declare and lock the dependency, or use an
  equivalent supported validator before claiming its tests pass.
- The reference's Codex-credit rate table was not independently validated by
  this assessment. Keep it versioned, source-attributed, and explicitly
  provisional until verified. API-equivalent dollars are a comparison metric,
  never an invoice claim.
- The existing app-server approval canary failed closed on this workstation;
  do not use that transport for a live A/B run.

The local `codex exec` probe emitted non-fatal model-cache diagnostics on
stderr. The harness must record a bounded diagnostic/status flag, never the
diagnostic body, and make unusable telemetry a validity failure.

## Required experiment contract

1. Both arms use the same pinned appservice revision, Terra model, reasoning
   setting, prompt, output schema, scoped read-only kubeconfig, and completion
   criteria. Use detached worktrees and isolated Codex homes.
2. A alone receives experiment-local `AGENTS.md` guidance, a health skill, an
   outctl wrapper requirement, and a dedicated local spool. B receives no
   model-visible outctl wording. Fail if B baseline guidance/config is
   contaminated.
3. Both arms use experiment-local, reviewed `PreToolUse` Bash guards. A denies
   direct kubectl and permits only the frozen wrapped read-only corpus; B
   permits only the same frozen direct read-only corpus and contains no outctl
   terms. Neither guard may accept shell chains, mutations, Secret reads,
   `exec`, `debug`, `port-forward`, or arbitrary resources/verbs.
4. Do not grant broad approval bypass. `--dangerously-bypass-hook-trust` is
   permitted only after the generated hook source and hash are captured in the
   dry-run report; never use `--dangerously-bypass-approvals-and-sandbox`.
5. Parse only the final single `turn.completed.usage` event from each JSONL
   stream. Persist raw JSONL/stderr only in mode-0700 private local storage;
   public reports contain hashes, counters, classifications, and paths only.
6. Keep cache accounting exact:

```text
noncached_input = input_tokens - cached_input_tokens
uncached_read = noncached_input - cache_write_input_tokens
```

Fail when any component is negative. Treat input/cmd-output bytes as
context-footprint proxies, never literal resident memory. Record cache write
separately. If a supported old CLI omits cache writes, return explicitly
labeled min/max ranges; current 0.146.1 must provide the exact field.

7. Pin and source the pricing table. Current API-equivalent Terra rates used by
the reference are input $2.00/M, cached $0.20/M, cache write $2.50/M, output
$12.00/M. Apply the documented long-context caveat above 272K request input;
with only an aggregate, return a range. Do not double count reasoning output.
8. Require a bounded JSON health-result schema, same overall health conclusion,
evidence-overlap gate, status/model verification, hook observation, exact A
capture/retrieval evidence, zero B outctl usage, bounded start skew, and
read-only command compliance before a pair is valid. Invalid pairs remain in
the report and are excluded from aggregate efficacy calculations.

## Implementation sequence

1. Unpack the transferred ZIP to a temporary review path and compare every
   file against this contract. Add the required dependency/lock update before
   running reference tests.
2. Introduce the harness under `acceptance/codex_appservice_ab/` only, with
   unit tests covering JSONL parsing, cost ranges, guard classification,
   baseline contamination, raw-free report validation, and a fake-Codex pair.
3. Run an offline dry run that creates no Codex session, kubeconfig call, or
   cluster connection. Inspect generated A/B guidance and hook hashes. Ensure
   B has no outctl vocabulary.
4. Run the full repository gates. Devbox-vm stops here: it must not use a
   cluster credential or live appservice A/B session.
5. Hand off the reviewed commit(s) and dry-run report metadata to workstation
   for a fresh scoped-credential wiring pair, then a separately authorized
   three-pair evaluation.

## Required verification

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
python /projects/dev/agentops/templates/dispatch/scripts/validate_verification_artifacts.py --root .
uv run outctl pilot smoke
```

Add and run the harness-specific tests as part of `uv run pytest`; do not leave
the external package's test file outside normal discovery.

## Authority and handoff classification

Devbox work is implementation/offline verification only. No push, pull request,
merge, kubeconfig use, appservice write, cluster access, or live Codex A/B is
authorized. Source host: workstation. Source path: `/projects/dev/outctl`.
Classification: host-persistent Git worktree plus a host-local reference ZIP;
neither is durable-authoritative. Raw command/model output is not part of this
handoff.
