# Concurrent Codex / appservice A/B pilot for outctl

This harness runs matched GPT-5.6 Terra health-check sessions against the same
appservice cluster state:

- **Arm A — guided treatment:** experiment-local `AGENTS.md` guidance, an
  `outctl-kubectl-health` skill, and a `PreToolUse` hook that requires every
  `kubectl` invocation through `outctl run`.
- **Arm B — unguided baseline:** the same repository revision, user prompt,
  model, Codex settings, output schema, and read-only Kubernetes guard, but no
  native mention of or routing to the treatment tool.

Each pair starts concurrently. Multiple pairs run sequentially so the test does
not turn a health check into an accidental load test.

## Evidence boundary and staged operation

The fake-Codex suite and dry run validate only harness wiring, report shape,
and policy generation. They do **not** demonstrate live outctl context, cost,
or health-quality efficacy. Do not make an efficacy claim until a real,
scoped-read-only wiring pair completes and a reviewer manually reconciles its
private JSONL/capture artifacts with the metadata-only report.

The first live operation is deliberately staged:

1. Run the offline dry run and inspect A/B guidance plus generated hook hashes.
2. Obtain separate authorization for one scoped read-only wiring pair.
3. Manually reconcile the private artifacts and public metadata report.
4. Only if that review passes, run three sequential matched pairs.

Backend prompt-cache sharing is a confound. Cache values are descriptive; the
decision metrics are total input, uncached-read input, model-visible command
output bytes, and weighted credits.

## Recommendation

Run **three concurrent pairs** and judge the median. One pair is useful only as
a wiring smoke test; stochastic agent behavior and prompt-cache timing are not
known for their respect for sample-size theatre.

Treat this as an **intent-to-treat test**: it measures the net effect of native
guidance plus enforcement plus bounded output, not the isolated byte-level cost
of the wrapper alone. That is the useful operational question for adoption.

## Why `codex exec --json` is the accounting source

Capture the final cumulative `turn.completed.usage` object from Codex JSONL.
Do not use the local SQLite state, history files, UI estimates, or a Stop hook as
the primary token ledger.

A minimal standalone capture looks like this:

```bash
umask 077
set -o pipefail
codex exec --ephemeral --json --model gpt-5.6-terra '<task>' \
  | tee events.jsonl

jq -c 'select(.type == "turn.completed") | .usage' events.jsonl | tail -n 1

# Apply the same validated accounting used by the A/B harness.
python acceptance/codex_appservice_ab/summarize_codex_usage.py events.jsonl
```

The harness records:

- total input tokens;
- cached input tokens;
- cache-write input tokens when the installed CLI emits them;
- non-cached input (`input - cached`);
- uncached-read input (`input - cached - cache_write`);
- cache-hit, cache-write, and uncached-read ratios;
- output tokens and reasoning-output tokens;
- Codex credits and API-equivalent US dollars;
- model-visible command-output bytes, including a kubectl-only subset;
- raw-free outctl manifest totals for retained stdout/stderr bytes and capture
  status; and
- duration, hook compliance, and final health-result parity.

Reasoning-output tokens are already contained in output tokens and are never
charged twice.

### Terra rate block pinned on 2026-08-08

For current token-based Codex accounting:

```text
uncached read input   50 credits / 1M
cached input           5 credits / 1M
cache write            0 credits / 1M
output                300 credits / 1M
```

For API-equivalent comparison:

```text
uncached read input   $2.00 / 1M
cached input          $0.20 / 1M
cache write           $2.50 / 1M
output               $12.00 / 1M
```

`api_equivalent_usd` is a comparison value, not an assertion that a
ChatGPT-signed-in session generated a dollar invoice. If a CLI version omits
`cache_write_input_tokens`, the harness reports honest minimum/maximum cost
bounds. If aggregate input exceeds 272,000 tokens, it also reports an API-cost
range because per-request long-context pricing cannot be reconstructed from a
session aggregate.

## Preconditions

1. `appservice` contains the health-check guidance/skills you want to test.
   Prefer a clean committed revision. Use `--allow-dirty` only deliberately;
   use `--include-untracked` only when you have reviewed every untracked file.
2. `outctl run` works from the canonical appservice direnv environment.
3. For every live run, pass an explicit dedicated read-only kubeconfig and its
   exact `--context`. Before either model starts, the harness verifies the
   fixed health-check corpus permissions and rejects any identity that can
   mutate, read Secrets, exec, port-forward, or inject ephemeral containers.
   It injects the kubeconfig directly so neither arm can inherit or replace it
   through user-local environment setup.
4. Optionally pass appservice's `bin/cluster-status.sh` with
   `--health-checker`. The launcher runs it once with `TALOSCONFIG` cleared,
   retains its raw capture privately, and gives both arms the same bounded
   projection. It is shared context, not a treatment-side command.
4. Set an approved policy reference and its real SHA-256 digest. Do not use a
   decorative all-zero digest merely because the CLI accepts one.
4. Codex authentication is available through `$CODEX_HOME/auth.json` or
   `CODEX_API_KEY`.
5. Use a dedicated read-only Kubernetes identity if at all possible. The
   generated hook denies known mutation/interactive verbs and Secret reads,
   but a model hook is a guardrail, not cluster-side authorization.

Example variables:

```bash
export OUTCTL_POLICY_REF='appservice-health-v1'
export OUTCTL_POLICY_DIGEST='sha256:<64-hex-approved-policy-digest>'
export AB_ROOT="/projects/dev/_projects/codex-appservice-ab/$(date -u +%Y%m%dT%H%M%SZ)"
```

## Review the generated treatment before spending tokens

A dry run does not require Codex authentication or cluster access:

```bash
cd /projects/dev/outctl
uv run python acceptance/codex_appservice_ab/run.py \
  --appservice /projects/dev/appservice \
  --canonical-appservice /projects/dev/appservice \
  --outctl-cmd 'uv run --project /projects/dev/outctl outctl' \
  --policy-ref "$OUTCTL_POLICY_REF" \
  --policy-digest "$OUTCTL_POLICY_DIGEST" \
  --pairs 3 \
  --output "$AB_ROOT-dry" \
  --dry-run \
  --keep-worktrees
```

Review these files:

```bash
sed -n '1,240p' "$AB_ROOT-dry/worktrees/A/AGENTS.md"
sed -n '1,240p' \
  "$AB_ROOT-dry/worktrees/A/.agents/skills/outctl-kubectl-health/SKILL.md"
cat "$AB_ROOT-dry/worktrees/A/.codex/hooks.json"
cat "$AB_ROOT-dry/worktrees/B/.codex/hooks.json"

# Expected: no matches in B's model-visible native guidance/config.
rg -n -i 'outctl' \
  "$AB_ROOT-dry/worktrees/B/AGENTS.md" \
  "$AB_ROOT-dry/worktrees/B/.agents" \
  "$AB_ROOT-dry/worktrees/B/.codex" || true
```

The B-side generated read-only guard intentionally contains no treatment
vocabulary. Existing B guidance is scanned before launch; the harness fails
closed if it already mentions the treatment unless you explicitly accept a
contaminated baseline.

## Run the authorized wiring pair

Use a new output directory:

```bash
export AB_LIVE="/projects/dev/_projects/codex-appservice-ab/$(date -u +%Y%m%dT%H%M%SZ)"

cd /projects/dev/outctl
uv run python acceptance/codex_appservice_ab/run.py \
  --appservice /projects/dev/appservice \
  --canonical-appservice /projects/dev/appservice \
  --kubeconfig /path/to/read-only.kubeconfig \
  --context outctl-pilot-readonly@appservice \
  --health-checker /projects/dev/appservice/bin/cluster-status.sh \
  --outctl-cmd 'uv run --project /projects/dev/outctl outctl' \
  --policy-ref "$OUTCTL_POLICY_REF" \
  --policy-digest "$OUTCTL_POLICY_DIGEST" \
  --model gpt-5.6-terra \
  --pairs 1 \
  --timeout-seconds 1800 \
  --output "$AB_LIVE"
```

Do not run this command without separately authorized, scoped read-only
credentials. After manual artifact/report reconciliation, repeat the command
with `--pairs 3` for the sequential matched evaluation. The launcher uses:

- detached worktrees at the same appservice commit;
- isolated per-arm Codex homes;
- web search, apps/plugins, persistent and imported memories, multi-agent
  execution, goals, and fast mode disabled;
- `--ephemeral` sessions;
- a generated least-privilege Codex permission profile, rather than a broad
  `--sandbox` override: model commands are read-only, A can write only its
  private outctl spool, and sandboxed network access is limited to the one API
  endpoint resolved from the explicit kubeconfig;
- `--dangerously-bypass-hook-trust` only for the generated experiment-local
  hook definitions, which are reviewed in the dry run;
- an experiment-only `hooks.json` in each detached worktree; any existing
  appservice hook file is not activated and its SHA-256 is recorded in the
  report, so the bypass cannot silently trust unrelated project hooks;
- a start barrier and alternating local thread-start order;
- one A-only spool per pair;
- treatment-side `OUTCTL_ENABLED=1` and `OUTCTL_MODE=enforce` applied after
  `direnv exec`, so an inherited break-glass setting cannot silently convert
  the treatment into bypass mode;
- automatic deletion of copied Codex credentials and session homes.

## Read the result

```bash
jq '.experiment, .aggregate' "$AB_LIVE/report.json"
jq '.pairs[] | {pair, pair_valid: .comparison.pair_valid, flags: .comparison.flags}' \
  "$AB_LIVE/report.json"
```

Aggregate medians use **valid pairs only**. The report keeps invalid pairs and
their flags, but does not quietly blend broken hook loading, divergent health
results, or missing captures into the efficacy result.

### Validity gates

Reject or repeat a pair when any of these fail:

- both arms exit successfully without timeout;
- both emit a fully Draft 2020-12 schema-valid structured result;
- both hooks are observed;
- both hook streams identify the requested Terra model with no reroute or
  fallback signal;
- A completes all `kubectl` work through `outctl`;
- A has exactly one finalized `COMPLETE` outctl capture for each completed
  wrapped `kubectl` command, with no partial captures, missing manifests, or
  unreadable manifests;
- B does not spontaneously use `outctl`;
- neither arm attempts a non-read-only Kubernetes operation;
- both reach the same overall health status;
- structured evidence Jaccard overlap is at least `0.60`;
- process launch skew stays below `250 ms`.

`treatment_first_try_compliant` is stricter than `treatment_compliant`: it is
false when the model first tries direct `kubectl` and only corrects after a hook
denial. That distinction tells you whether the skill worked or the guard merely
caught it at the fence.

### Initial efficacy gates

For a first production decision, I would use:

```text
median model-visible command-output bytes reduction   >= 50%
median model-visible kubectl-output bytes reduction   >= 50%
median total input-token reduction                    >= 20%
median uncached-read input-token reduction            >= 20%
median Codex-credit reduction                         >= 15%
median wall-time regression                           <= 20%
health-result quality                                  non-inferior
```

Do not use absolute cached-token count as a pass/fail metric. A may cache a
larger guided prefix while still consuming fewer total and uncached tokens.
Prefer total input, uncached-read input, cache-hit ratio, and weighted cost.

A flat output-token result is not a failure: both arms are required to return a
similarly bounded health report. The expected gain is primarily command output
no longer being dragged through every later model request.

For Arm A, `arm_a_outctl_exposure_ratio` compares the JSON/projection bytes
visible to Codex with the retained stdout/stderr byte total from outctl
manifests. It is a mechanism check, not a token substitute: serialization,
tokenization, retrieval calls, and non-kubectl commands still matter.

## Private artifacts

`report.json` contains metrics, hashes, counts, and paths. Raw material remains
under:

```text
$AB_LIVE/private/pair-NNN/A/events.jsonl
$AB_LIVE/private/pair-NNN/A/stderr.log
$AB_LIVE/private/pair-NNN/A/final.json
$AB_LIVE/private/pair-NNN/A/hook-events.jsonl
$AB_LIVE/private/pair-NNN/outctl-spool-A/
```

The B arm has equivalent Codex artifacts except for an output spool. Codex JSONL
can contain command output; keep the run root private. The harness creates it
with mode `0700` and report/private files with mode `0600`.

## Cleanup and rollback

Normal live execution removes worktrees and Codex homes automatically. A dry
run with `--keep-worktrees` deliberately does not:

```bash
git -C /projects/dev/appservice worktree remove --force \
  "$AB_ROOT-dry/worktrees/A"
git -C /projects/dev/appservice worktree remove --force \
  "$AB_ROOT-dry/worktrees/B"
git -C /projects/dev/appservice worktree prune
rm -rf -- "$AB_ROOT-dry"
```

No experiment overlay is written to the canonical appservice worktree. To roll
back the implementation itself, remove `acceptance/codex_appservice_ab/`.

## Known limitations

- Concurrent sessions can share backend prompt-cache entries for common
  prefixes. Codex does not expose a cache-isolation key here. Repeated matched
  pairs and launch-skew recording reduce, but do not eliminate, that confound.
- Codex exposes token/cache accounting, not literal resident session-memory
  bytes. Input tokens, uncached input, and model-visible output bytes are the
  relevant context-footprint proxies.
- The shell classifier covers ordinary Bash/unified-exec calls. Hooks are not a
  complete security boundary; use Kubernetes RBAC for that job.
- Cluster state can still change during the pair. Concurrency narrows the
  window; it does not freeze reality, which Kubernetes traditionally considers
  an optional feature.
- The pinned rate block must be reviewed when OpenAI changes Terra pricing.

## Local validation

```bash
cd acceptance/codex_appservice_ab
uv run python -m unittest -v
uv run python -m py_compile run.py kubectl_guard.py kubectl_readonly_guard.py \
  summarize_codex_usage.py test_run.py
```

The test suite includes guard classification, baseline-blinding checks,
cache-write fallback accounting, exact Terra accounting, and a fake concurrent
Codex end-to-end run.
# Codex appservice A/B acceptance harness

`run.py` has two deliberately distinct treatments:

- `--treatment-mode deterministic` (the default) is the commissioning/mechanism
  benchmark. It requires every `kubectl` call through the bounded router and
  exactly one bounded retrieval. A bootstrap failure aborts later pairs.
- `--treatment-mode opt-in` is an exploratory UX trial. Arm A receives a short
  `outctl-health` skill and helper for likely-large output, while direct
  read-only `kubectl` remains allowed. The report records adoption and
  retrieval behavior; non-adoption is not a validity failure and its cost
  numbers must not be presented as deterministic compression results.

Both modes keep the same read-only/secret-denial guard and private spool.
