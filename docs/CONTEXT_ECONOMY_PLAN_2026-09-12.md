# Context economy plan: what to do about the 38%

**Date:** 2026-09-12
**Inputs:** [`REASSESSMENT_2026-09-12.md`](./REASSESSMENT_2026-09-12.md) (measurements),
owner's tool shortlist (RTK, snip, Context Mode, Headroom), owner's structured
handoff requirement (prepare → validate → launch → acknowledge → transfer).
**Scope:** plan only. No tool is installed and nothing outside this file changed.

## 0. The answer to "why is 80% of context Bash if the tools exist"

Because the harness *tells* the model to read files through Bash. Every session
in the corpus carries the attachment `auto_mode{bashFirst:true, bashFirstSteer:"strict"}`,
rendered as: *"read files with cat, head, or sed -n … rather than using the
dedicated Read, Edit, or Write tools"*. The measured consequence:

| Bash result bytes by class | Share | What a filter can do about it |
| --- | ---: | --- |
| file reads (`cat`, `sed -n`, `head`, heredocs) | 60% | nothing useful: the model asked for the content |
| git / gh / fj | 18% | RTK/snip filter `git status/log/diff` well |
| kubectl / flux / systemd / nix / ssh | 13% | RTK/snip cover kubectl, docker; not flux, talosctl, nix, journalctl |
| tests / lint / build | 3% | RTK/snip cover pytest, ruff, go, cargo |
| search / listing | 3% | RTK/snip cover ls, find, grep |
| python / curl / jq | 2% | no |

So the cost is not shell noise. Exact-duplicate outputs are ~0% and error
outputs 1.5%; overlapping excerpts were not measured, and how much of the
read content was unnecessary is not established. All shares are transcript
bytes, not live-context tokens; the owner's `/context` (37%) is the only
live calibration point. Tool choice and read size are separate variables:
`sed -n` bounds a read as well as Read with `limit`, and the same content
costs the same either way. The harness spool (`tool-results/`)
catches the rare >30 KB result. The remaining cost is **reading whole files
and long ranges into the parent context** when a subagent, a bounded Read, or a
grep would have done. The worst sessions were 92 to 100% file reads.

The steer is selected in the binary by
`process.env.CLAUDE_CODE_COZY_TEAPOT ?? <feature flag> ?? "strict"`, with a
`"relaxed"` variant present (Claude Code 2.1.269). That is an unstable internal
knob and is listed as an experiment, not a dependency.

## 1. Existing tooling the solution must mesh with

| Component | What it already does | Path |
| --- | --- | --- |
| Claude hooks (workstation) | `SessionStart` session-binding (resolved-context invariant), `Stop` cost log + auditctl `workflow.session` event, `SubagentStop` exit record with actionq reason codes | `/projects/dev/.claude/hooks/{session-binding,log-session-cost,subagent-exit}.sh`, `~/.claude/settings.json` |
| Same hooks on devbox agent identity | deployed read-only from gitops-nixos, `bypassPermissions` | `gitops-nixos/modules/system/hybrid-dispatch/claude-settings.json` |
| Other hooks present but not wired globally | forge-context, forge-sandbox-guard, gate-check/gate-log, secret-read-guard, homelab-context, sprintctl-maintain-check, push-landed-check | `/projects/dev/.claude/hooks/` (14 scripts) |
| sprintctl | `sprintctl handoff --format json|text` emits a working-memory bundle (sprint, items, last 50 events); takeup is a visibility signal with no ownership | `sprintctl/docs/examples/agent-prompt-snippets.md:52`, `sprintctl/docs/advanced/takeup.md` |
| agentops | prose handover convention already in use, cold-session oriented (state, where work stands, unpushed changes, traps); session-resolved-context contract; dispatch driver `hybrid-dispatch` | `agentops/docs/dispatch/handover-2026-08-25-session-close.md`, `agentops/docs/contracts/session-resolved-context.md` |
| auditctl | validated event vocabulary already consumed by the Stop and SubagentStop hooks | via `subagent-exit.sh` |
| Vuoro | portable-execution says a candidate-ready worker "emits a structured handoff immediately"; Vuoro transports reference, cursor, state; Actionq owns lifecycle; Auditctl owns findings | `vuoro/docs/architecture/portable-execution.md:117,221` |
| Session archive | `profiles.claudeSessionsArchive.enable = true` in `hosts/workstation/default.nix:139`; module merged 2026-09-12 12:24, system rebuilt 12:35; `claude-sessions-archive.timer` active, service has not fired yet | `gitops-nixos/modules/system/claude-sessions-archive.nix` |
| Codex | codex-cli 0.153.4 with `app-server` (daemon/proxy); global `~/.codex/AGENTS.md`; no hooks.json | `~/.codex/config.toml` |
| Status line | already shows `ctx:NN%` from `context_window.used_percentage` | `~/.claude/settings.json` statusLine |

Correction to the reassessment §4: the archive control **is deployed as of
today's rebuild**, one hour after the reassessment was written. Verified 2026-09-12 by a manual
service run: 225 sessions archived under
`/mnt/truenas/storage_layer/vault/backups/claude-sessions/`, index and
sha256 present. The `feat/claude-session-archive` branch is superseded by the
merged module and should be deleted.

## 2. The four tools against the measured bytes

| | RTK | snip | Context Mode | Headroom |
| --- | --- | --- | --- | --- |
| Mechanism | Rust binary; PreToolUse hook rewrites `git status` → `rtk git status` | Go binary; PreToolUse `updatedInput` rewrite driven by 132 YAML filters | MCP server + 5 hooks; blocks Bash/Read and routes through sandboxed `ctx_execute`; SQLite FTS index; PreCompact/SessionStart snapshot | Python proxy/library/MCP; content-typed compressors; reversible with `headroom_retrieve`; cache-prefix aligner |
| Bytes it can touch here | git 18% + infra ~8% (kubectl, docker) + tests 3% + search 3% ≈ **30%** | same ≈ 30%, plus helm/terraform (unused here); flux/talosctl/nix/journalctl need custom YAML | up to 100% by routing every read/exec through it; the model then *searches* instead of reads | all tool output incl. file reads (CodeCompressor) |
| Realistic reduction of the 38% | ~30% × 60-90% filter ≈ **7–10 points** | same, ~7–10 points | unknown; changes the working style, not just the bytes | claims 20% on coding agents ≈ 7 points; JSON-heavy sessions more |
| Claude Code | native, `rtk init -g` | native hook, `snip init` | plugin marketplace | wrapper of `claude` |
| Codex | hooks.json, deny-with-suggestion | native PreToolUse rewrite ≥ 0.131 | MCP + deny-only hooks | wrapper |
| Second execution layer | no (10 ms, same process tree) | no (<10 ms) | **yes** (subprocess sandbox + index) | proxy in the API path |
| Failure modes | silently filtered failure detail; `rtk recall <hash>` exists but the model must know to use it; telemetry on by default | same class; `snip proxy --` bypass; global caps can cut a needed line | routing compliance ~60% without hooks; index staleness (24 h TTL); every read becomes a search round trip | prefix-cache invalidation if aligner misjudges; prose model dependency; opaque compression of code the model is editing |
| Maintenance | none, but Rust fork to add flux/talosctl/nix | YAML per command, trust-scoped, fits gitops-nixos deployment | plugin + SQLite store per host; interacts with the existing five hooks | Python service, model download, proxy in the credential path |
| Interaction with existing hooks | additive PreToolUse | additive PreToolUse | **conflicts**: it wants PreToolUse/PostToolUse/SessionStart/PreCompact; session-binding and cost hooks must be merged with it | none at hook level; sits in front of the API |

**Recommendation and order**

1. **snip** first, not RTK. Same byte coverage, but the flux / talosctl /
   nix / journalctl / sops gap that dominates this owner's infra class is a
   YAML file, not a Rust fork, and the YAML is deployable from gitops-nixos to
   the workstation and the devbox agent identically. Hook rewrite via
   `updatedInput` is the same mechanism the owner's own hooks would use. Codex
   coverage is native.
2. **RTK** only if snip's filters prove weaker on git/pytest in the gate below.
   Do not run both; two rewriting PreToolUse hooks on one Bash call is
   undefined ordering.
3. **Headroom**: defer. It is the only one that can touch the file-read 60%,
   but at the price of a proxy in the API path and opaque compression of code
   the model is editing. Revisit only if phase 2 below fails to move the
   file-read share.
4. **Context Mode**: reject for now. It is outctl's thesis rebuilt as an MCP
   server plus a search index, adds a second execution layer, and collides
   with the session-binding, cost, and subagent-exit hooks. Its PreCompact
   snapshot idea is the one piece worth borrowing, and phase 3 does that
   natively.

Ceiling to state plainly: filters address at most about a third of Bash
bytes, so roughly 10 points of the 38%. The other 60% needs phase 2.

## 3. The file-read 60%: levers and estimated effect

| Lever | Mechanism | Estimated effect on the 60% | Risk |
| --- | --- | --- | --- |
| A. Read-tool with offset/limit instead of `cat`/`sed -n` | permit Read in the auto-mode steer (`CLAUDE_CODE_COZY_TEAPOT=relaxed` experiment, or a project instruction in `AGENTS.md`/`CLAUDE.md` that overrides the reminder for reads) | Bytes are the same per line read; gain comes from `limit` discipline and from line-numbered reads being harder to `cat` whole. Expect 10–20% of file-read bytes | Unstable internal env var; steer text may change per version |
| B. PreToolUse guard: unbounded `cat`/`sed -n` over a file > N lines returns a deny with a hint (`file is 733 lines; read a range or grep`) | shell hook, same pattern as `secret-read-guard.sh`; deny, do not rewrite, so behaviour stays visible | Targets the 242 results >10 KB that hold 22% of Bash bytes; the largest were `cat config.yaml` (24 KB, twice in one session), `cat -n scope-and-status.md`, `sed -n 1,733p`. Expect 15–20% of file-read bytes | Model may split into two reads and land at the same total; measure |
| C. Delegate reading to subagents by norm | project instruction: "reading more than ~200 lines of a file to answer a question goes to an Explore subagent that returns the conclusion" | Subagent transcripts already hold 12.1 MB of tool results against 5.5 MB in parents; the pattern works. Expect the largest single gain, 30%+, in analysis-heavy sessions | Subagent output still costs tokens and rate limit; only the *parent* context is spared |
| D. Rewrite hook `cat FILE` → `head -c 8000 FILE` | PreToolUse `updatedInput` | Comparable to B in bytes | Silent truncation the model does not know about; rejected, B is the visible form |
| E. Read-once cache | note in context which files were read; skip re-reads | Duplicate outputs measured at 0%; nothing to gain | — |

Do A, B, and C. Reject D and E on the measurements.

## 4. Structured handoff: design mapped to real plumbing

**Owner: agentops.** Vuoro transports references and states that workers
"emit a structured handoff", but Actionq owns lifecycle and Vuoro is a
control plane, not the place a workstation session writes a file. sprintctl's
`handoff` bundle is sprint memory (items, events), not session memory
(decisions, rejected approaches, uncommitted diff). agentops already owns the
prose handover convention, the session-resolved-context contract, the three
lifecycle hooks, and the dispatch driver. The handoff file is therefore an
agentops artifact; sprintctl's bundle is embedded by reference; Vuoro sees the
handoff id as an opaque reference the same way it sees a capture reference.

**Handoff file** (`agentops/docs/dispatch/handoffs/<date>-<slug>.v<N>.json`,
plus a rendered `.md` for humans; schema in `agentops/schemas/handoff.schema.json`):

```text
handoff_id, version, predecessor{harness, session_id, transcript_path, model, context_used_pct}
objective, constraints[], decisions[{what, why}], rejected[{what, why}]
state{repos[{path, head, branch, dirty:bool, diff_sha256, unpushed:int}], running:[]}
unresolved[], evidence[{kind: session|artifact|auditctl|sprintctl, ref}]
sprintctl_bundle_ref, next_action{exact text}, successor{session_id|null, acknowledged_at|null}
```

The `diff_sha256` is over `git diff HEAD` plus `git status --porcelain`, so a
successor can prove the tree is the one the predecessor left.

**Lifecycle on Claude Code**

| Step | Plumbing |
| --- | --- |
| Checkpoint trigger | status line already has `context_window.used_percentage`. Add a `UserPromptSubmit` hook that reads the same field from the transcript's last `usage` block and, above a threshold (start at 60% of the 1M window, which is where the corpus's long sessions sat when quality visibly dropped), injects one reminder: "prepare a handoff before new changes". Not a hard stop |
| Prepare | a `/handoff` skill in `/projects/dev/.claude/skills/` writes the file, runs `sprintctl handoff --format json`, computes repo state, validates against the schema, records `predecessor.session_id` from `$CLAUDE_SESSION_ID` |
| Validate | `agentops handoff validate <file>`: schema, every repo path exists, `head` resolves, `diff_sha256` matches now, `next_action` non-empty |
| Launch | `claude --bg --session-id <new-uuid> -p "$(agentops handoff prompt <file>)"` in the repo's cwd; or interactive: user runs `claude` and the existing `SessionStart` hook (`session-binding.sh`) finds a handoff whose `successor.session_id` is null and this cwd matches, and injects the rendered handoff as additional context. `initialUserMessage` only applies to `-p`, so the interactive path relies on the SessionStart injection |
| Acknowledge | successor's first action is `agentops handoff ack <id>`, which sets `successor.session_id` atomically (rename-based write, refuses if already set). This is the single-active-successor guard: a second launch finds `successor` set and exits with the id of the live one |
| Transfer | predecessor receives the ack via the file (its `Stop` hook checks and logs `workflow.session` with `handed_off_to`) and is parked: the user stops issuing turns to it. It stays consultable |
| Consult predecessor | `ListAgents` / `SendMessage` to the parked session for "why did you reject X"; a message starts a turn in the idle predecessor, billed against its full context, which is the intended cost shape. Constraint to encode in the predecessor's hand-off prompt: read-only, no edits, no external actions after transfer |
| Read predecessor transcript | the archive index (`claude-sessions-archive`) plus `tool-results/` give a successor exact bytes by session id without waking the predecessor |

**Lifecycle on Codex**: `thread/start` + `turn/start` with the rendered handoff
as the first user message for launch; `thread/read` for transcript access
without resuming; consultation requires resume + turn. Codex hooks are
deny-only today, so the SessionStart injection has no equivalent; the launch
path is always explicit through the app-server. Same file, same ack.

**Acceptance test** (the owner's "no predecessor access" test), as an
agentops verification artifact: take a real handoff, start a successor with
the predecessor's session directory made unreadable and `SendMessage`
unavailable, ask it to state the constraints and execute `next_action`.
Pass if the constraints match the file, the repo state check passes, and the
next action lands. Then repeat with a deliberately stale `diff_sha256` and
require refusal.

## 5. Rollout

Gate metric everywhere: re-run
`/tmp/claude-1000/-projects-dev/75f65a35-f426-49bc-9638-b09003838075/scratchpad/{measure,classes,waste}.py`
(copy them to `outctl/studies/context-economy/` first; the scratchpad is
session-scoped) over sessions started after the change. Primary number: Bash
share of top-level session content (baseline 38%). Secondary: file-read share
of Bash bytes (60%), results >10 KB (242 / 8,523).

| Phase | Change | Gate to pass | When |
| --- | --- | --- | --- |
| 0 | Confirm archive; delete `feat/claude-session-archive` | **Done 2026-09-12**: manual service run archived 225 sessions, index and sha256 verified; local branch deleted, remote copy remains; stale Forgejo-token claim fixed in `agentops` (`0c4e01c`) and `~/.codex/AGENTS.md` | done |
| 1 | snip on the workstation only, `snip init`, YAML for `flux`, `talosctl`, `journalctl`, `nix build`, `sops`; keep `snip proxy --` documented in AGENTS.md | **Built 2026-09-12** (`gitops-nixos` `03b2363`, nixpkgs snip 0.24.1 via devtools; filters in `modules/system/snip/filters/`, home-manager links them; bypass documented via agentops template `187fa74`). Switched and hook installed 2026-09-12 via `snip-hook-defer.sh` (snip's own hook answers `allow` for every matched command, which would bypass the permission classifier for `git push`/`kubectl delete`; the wrapper keeps the rewrite and drops the decision; an explicit `defer` was observed to leave subagent Bash calls without a result, ending their turns, `f771c22`). Gate: git+infra+tests share of Bash bytes drops ≥ 40% with no lost failure line in 10 sessions | measuring |
| 2 | file-read levers A + B + C: instruction change, cat/sed guard hook, Explore-delegation norm | **Implemented 2026-09-12**: `CLAUDE.md` bounded-reads rule; `/projects/dev/.claude/hooks/bounded-read-guard.sh` (deny-with-hint, 34 tests pass) wired in project `settings.json`. Gate still to measure on sessions started after today: file-read share of Bash bytes < 45%; Bash share of session < 28% | measuring |
| 3 | handoff skill + validate + ack + SessionStart injection on Claude Code; schema in agentops | **Implemented 2026-09-12** on `agentops` branch `handoff-v1` (`f44a6af`): schema, `handoff.py` create/validate/prompt/ack/render, `bin/agentops` shim, 30 tests; `/handoff` skill; threshold and session-start hooks wired in project `settings.json`. **Gate passed 2026-09-12** (`1c5f8ac`): fresh successor `75868138…` acked first, restated constraints, landed next_action; stale-diff successor `2615539c…` refused; isolation simulated (same uid), enforced isolation deferred to the phase 4 Codex/devbox run. Stop hook records `handed_off_to` (`d321ead`) | done |
| 4 | Codex path via app-server; snip on devbox agent identity via gitops-nixos | **Codex half passed 2026-09-12** (`b6b60dc`): `handoff_codex.py` launch/read/consult over app-server stdio; threads `01a09576…` (fresh, pass) and `01a09578…` (stale untracked drift, refused). `thread/read` with turns is unsupported on codex 0.153.4, so `read` parses the rollout file. Digest v2 (untracked content hashed, versioned) and cross-host ack write-back to `origin_host` landed in `2e357f1` (92 handoff tests pass). **Enforced isolation passed 2026-09-12** (`9974beb`): successor as `agent@devbox` with `/home/bayleaf` absent; Run E fresh 4/4 (session `a7c1ab5e…`), Run F stale untracked-content drift refused 4/4 (`fbbe153e…`), digests v2 computed on devbox. Not exercised: cross-host ack write-back (no `agent@devbox -> bayleaf@workstation` ssh path; handoffs used `origin_host: devbox`). snip for the agent identity built in `gitops-nixos` `549b7ba` (push + `nxrs` to deploy; needs `handoff-v1` on the devbox agentops clone or merged to main). Defect found: the harness audit hooks write `.auditctl/` and `_artifacts/` inside the repo under test, so a handoff whose repo is the successor's cwd cannot validate; launch from outside the repo until those paths are gitignored | done, write-back untested |
| 5 | Headroom trial only if phase 2 misses its gate | — | deferred |

Gate status: phases 0, 2 and 3 are implemented as of 2026-09-12.
Codex acceptance: 2026-09-12.

**Try first this week:** phase 0 and phase 1. Both are a day's work and the
gate is the same script that produced the baseline.

**Defer:** Headroom, the `CLAUDE_CODE_COZY_TEAPOT` experiment beyond a single
measured session (unstable knob), RTK.

**Reject:** Context Mode, rewrite-based truncation (lever D), any revival of
outctl's projection layer, running two rewriting hooks at once.

## Open questions for the owner

- Threshold for the checkpoint reminder: 60% is a guess from the corpus; the
  status line already shows the number, so the first two handoffs can be manual
  to calibrate.
- Whether `agentops` is willing to own a JSON schema for handoffs alongside its
  prose convention, or whether the prose file stays canonical with a JSON
  sidecar. The ack guard needs the JSON either way.
