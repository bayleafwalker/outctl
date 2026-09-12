# Session-evidence frequency count: the shim does not clear its bar

**Date:** 2026-08-16
**Status:** decided — build the retention control, do not build the capture shim
**Relates to:** [`DISCOVERY_KILL_2026-08-16.md`](./DISCOVERY_KILL_2026-08-16.md)

## Why this count exists

`DISCOVERY_KILL_2026-08-16.md` kills the outctl product thesis and keeps one
bounded replacement-first spike: a thin capture adapter feeding OTel and an
object store, tested by starting a successor agent with only a session ID and
asking it for an exact historical fact.

That spike proves the **mechanism** works. It cannot prove the **situation
occurs**. The value hypothesis — that a successor agent needing point-in-time
evidence from a prior session is a recurring event in this work rather than a
plausible one — was still untested, and is answerable retrospectively for free
against session artifacts that already exist.

Decision rule agreed in advance: **a few times a month, build the shim; twice a
year, set `cleanupPeriodDays: 3650` plus a nightly tar indexed by session id** —
and treat that as the control the shim must beat.

## Corpus

195 Claude Code session transcripts under `~/.claude/projects`, dated
2026-07-17 to 2026-08-16, 184 MB, 12,403 Bash invocations, 19,404 tool results.

## Result

| Signal | Raw hits | Verified | Survives scrutiny |
| --- | ---: | ---: | ---: |
| Successor re-ran a command whose output already existed | 49 commands / 12 days | 12 | ~0 |
| Handoff lost a detail someone had to reconstruct | 227 | 8 | ~1 |
| "What did it look like before the repair" | 186 | 1 | 1 |

The reductions carry the finding.

**Reruns.** The 18 "expensive" recurring commands are `git push origin main`,
`flux reconcile source git cluster`, `kubectl rollout restart deploy/tdarr`,
`uv run pytest -q`, `mise run validate`, `sprintctl doctor`. These are
idempotent actions and current-state checks. `flux reconcile` recurs on five
days because reconciliation happened five times, not because the first output
was lost. No archive would ever serve these; the current answer is the point.
Notably, `kubectl get pods -A -o wide` — the command shape the spike is built
around — does not appear in the recurring set at all.

**Handoffs.** The exemplars are handoffs *succeeding*: "Session continued from
previous conversation that ran out of context. Summary covers earlier
findings." Compaction summaries and handoff notes doing their job. One case
resembles loss — 2026-08-13, vuoro-cloud, "Lost the instructive text on how to
do this" — and that is prose, not a tool result. A blob store keyed by sha256
would not have helped.

**Point-in-time asks.** One genuine instance in a month: 2026-08-06,
appservice, session `c67d42b0-fad0-47ed-8e85-c6cf9a8ebbe7` — the `k8s-control-3`
UEFI NVRAM state, with its malformed `Boot0004` entry, as it stood before the
EFI fix. Irrecoverable by re-running anything. Every other candidate resolved
to `git show` or to a file already saved under `_artifacts/`.

**One a month, not a few a month. By the stated rule, that is the tar.**

## The control is sufficient, contrary to first reading

An initial pass reported that 36 of 195 sessions contained truncation markers
and concluded the tar preserves the loss rather than the evidence. That was a
literal-string grep over a corpus in which several sessions *discuss*
truncation. It does not hold.

Scoped to actual `tool_result` payloads, the marker hits are prose and program
output — `truncated for a not-found explicit target (#1160)`, `truncated prompt
if no value provided) [string]` (CLI help), `truncated; use '--show-trace'` (a
nix error). No genuine harness truncation markers. Measured distribution across
19,404 tool results:

```text
p50    409 B
p90  3,386 B
p99 14,263 B
max 64,208 B      >50 KB: 6      >100 KB: 0
```

A ceiling exists — two payloads sit at exactly 64,208 bytes — but both are the
same document read through the `Read` tool, and its content is in git. Not live
cluster state. **Tool results reach disk essentially intact.** That is the fact
that decides the question, and it decides it against the shim: the shim's
central claim is capture *before* truncation, and there is nothing material
being truncated.

## The finding neither option anticipated

`cleanupPeriodDays` was **not set**, so the 30-day default applied. The oldest
surviving transcript was dated exactly 30 days before the count. The corpus was
not a month old because the work began a month ago; it was a rolling window
whose tail was being deleted continuously. Evidence was being lost already —
not to harness truncation, but to routine cleanup — and the fix was one line of
configuration.

## What was done

1. `cleanupPeriodDays: 3650` set in `~/.claude/settings.json`.
2. `scripts/claude-sessions-archive.sh` in `gitops-nixos`: nightly `tar` of
   `~/.claude/projects` to `/mnt/truenas/storage_layer/backups/claude-sessions/`,
   with a `index.tsv` mapping session id to date, size, and path, plus a
   SHA-256 of the tarball. Verified: 195 sessions, 46 MB compressed, and the
   2026-08-06 UEFI session is addressable by id.
3. `scripts/systemd/claude-sessions-archive.{service,timer}`, matching the
   existing `projects-snapshot-*` pattern. The existing Btrfs snapshots cover
   `/projects` on a rotating 7-day window and do not cover `~/.claude/projects`;
   this is additive, not a duplicate.

The shim is not built. The spike in `DISCOVERY_KILL_2026-08-16.md` should not
be run on the strength of the value hypothesis, because the value hypothesis
did not survive measurement.

## Limits on this count

- **Wrong harness, possibly.** It covers Claude Code sessions only. The Codex
  app-server Luna commissioning that motivated the design doc is not in this
  corpus. If the need concentrates in Codex or OpenCode work, this measured
  somewhere else.
- **Thin sample.** Only the 30 days that survived deletion were visible — which
  is itself an argument for fixing retention before drawing conclusions.
- **Nightly full tars grow superlinearly.** A full tar of a growing directory
  every night is O(n²) in total stored bytes. The script takes an optional
  retention count (default: keep everything). If the archive gets unwieldy,
  switch to an rsync mirror with periodic tar checkpoints rather than raising
  the prune count.

**Re-run this count in three months** against a corpus that no longer
self-deletes. If irrecoverable asks are still about one a month, the question
is closed for good.
