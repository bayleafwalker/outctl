# Core-premise reassessment against workstation sessions

**Date:** 2026-09-12
**Corpus:** every Claude Code transcript under `~/.claude/projects` on the
workstation: 34 top-level sessions and 186 subagent transcripts, 2026-09-04 to
2026-09-12, 135 MB, 8,523 Bash invocations, 10,111 tool results.
**Supersedes for the "context author" question:**
[`EVIDENCE_FREQUENCY_COUNT_2026-08-16.md`](./EVIDENCE_FREQUENCY_COUNT_2026-08-16.md),
which measured the successor-evidence hypothesis only.

## Verdict

The kill decision stands, and it is now over-determined. The design doc's
premise (`DESIGN.md` §2) had two halves:

1. Bash output is a major author of live context. **Confirmed, and larger
   than measured in August.**
2. Much of it is avoidable through a bounded head/error/tail projection with
   later retrieval. **Refuted on this corpus**, for three independent reasons
   below.

Separately, the control that replaced outctl on 2026-08-16 (retention plus a
nightly tar) was activated on this machine only today, and the August corpus
it was meant to protect is gone. See section 4.

## 1. Bash output share: premise half one holds

| Scope | Bash result share of message content | Bash share of all tool results |
| --- | ---: | ---: |
| Top-level sessions | 38% | 86% |
| Subagent transcripts | 48% | 89% |
| Design doc figure (Aug 3, one session) | 33% | — |
| Owner's `/context` sample (Sep 12) | 37% of occupied context | — |

Four sessions ended above 750k tokens on a 1M window with Bash at 28–49% of
their content. Bash is the dominant context author. That part of the premise
was right.

## 2. Why the projection would not have helped

**The harness already does the capture.** Claude Code spools any oversized
tool result to `<session>/tool-results/<id>.txt` and returns a preview ending
in `... [N lines truncated] ...` plus the path. This corpus has 29 such
spools (median 37 KB, largest 775 KB) and 18 tool calls that went back and
read one without re-running the command. That is outctl's capture, bounded
projection, and no-rerun retrieval, natively. It fired on 0.3% of Bash calls.

**The volume is not in large results.** Per-result Bash sizes:

```text
p50     768 B
p90   4,653 B
p99  13,365 B
max  29,444 B      >30 KB: 0      >10 KB: 242 (22% of Bash bytes)
```

Nothing exceeds the harness cap. 78% of Bash bytes sit in results under
10 KB. A projection that bounds each result cannot recover much from results
that are already small; the cost is the count of calls, not their size.

**The bytes are content the model asked for, not shell noise.** Whether
all of it was necessary is not established by this count; exact-duplicate
results are ~0% of bytes, but overlapping excerpts were not measured. Bash result
bytes by command class:

| Class | Share of Bash bytes | Calls |
| --- | ---: | ---: |
| File reads (`cat`, `sed -n`, `head`, heredocs) | 60% | 3,701 |
| git / gh / fj | 18% | 1,660 |
| kubectl / flux / systemd / nix / ssh | 13% | 1,783 |
| tests, lint, build | 3% | 657 |
| search and listing | 3% | 486 |

Sixty percent is file content read through Bash because auto mode instructs
the agent to prefer `cat`/`sed -n` over the Read tool. A head/error/tail
projection of a file the model chose to read is a worse Read tool. The class
the design was built around, cluster and log output, is 13%, and tests are 3%.
The design doc's example of "repeated progress, passing tests, recursive
listings" describes about 6% of the bytes.

**The model already filters.** 80% of top-level Bash commands (73% overall)
carry a bounding operator (`head`, `tail`, `grep`, `sed -n`, `--stat`,
`-maxdepth`, and so on). Bounded commands still account for 59% of Bash
bytes, because a bounded read of a file is still the file. The "elementary
filtering" the design proposed is happening at the command line, unpaid.

## 3. What the 38% actually is

Working through the largest sessions, Bash context is dominated by reading
source, docs, and configs, in many medium-sized pieces, with `git log`/`diff`
second. The lever on that is not a projection layer. It is the choice of what
to read and whether to delegate reading to a subagent whose transcript does
not return to the parent. The corpus already shows that pattern: subagent
transcripts carry 12.1 MB of tool results against 5.5 MB in the parents.

Two cheap, real levers remain, neither of them outctl:

- Reading via the Read tool with `offset`/`limit` instead of `cat` where auto
  mode allows it, so the harness's own line-numbered, bounded read applies.
- The `/context` suggestion the harness already prints ("pipe through head,
  tail, or grep") is the entire remaining recommendation.

## 4. The control: deployed today, not yet exercised

The August count recorded a retention setting plus a nightly tar. On this
machine:

- `~/.claude` was created on 2026-09-04 (workstation rebuild). The earliest
  surviving transcript is from that day. The 195-session August corpus is not
  here, so the "re-run in three months against a corpus that no longer
  self-deletes" instruction cannot be honoured as written.
- `cleanupPeriodDays: 3650` is set in the rebuilt `settings.json`.
- The archive is a NixOS module, `gitops-nixos/modules/system/claude-sessions-archive.nix`,
  enabled in `hosts/workstation/default.nix` and activated by a rebuild on
  2026-09-12 12:35, after this session's first check found no timer.
  `claude-sessions-archive.timer` is enabled; first run 2026-09-13 00:13.
  The destination, `/mnt/truenas/storage_layer/vault/backups/claude-sessions`,
  is writable by the service user through an NFSv4 ACL that `getfacl`
  does not render (an earlier reading of the mode bits as a permission
  failure was wrong). A manual run of the deployed service on 2026-09-12
  archived 225 sessions (35 MB), with `index.tsv` and a verified SHA-256.
  Residual: the NAS-inherited ACL defeats the service's `UMask 0077`, so
  artifacts are group-readable; NAS-side fix, not NixOS-side.
- `feat/claude-session-archive` (`92eb9b3`) is superseded by the module and
  should be deleted.

The branch is deleted locally; a remote copy remains on `github`.

## 5. Successor-evidence hypothesis, re-checked

The only genuine irrecoverable ask in August was one UEFI NVRAM state in one
month. Nothing in this eight-day corpus adds a second: the truncation markers
present are the harness's own spool previews, whose full bytes are on disk
next to the transcript. The rule agreed in advance ("a few a month builds the
shim; twice a year sets retention and tars") still lands on the tar.

## Limits

- All shares are transcript-byte shares, not live-context token shares.
  Tool choice and read size are separate variables: `sed -n` bounds a read
  as well as Read with `limit` does, and the same content costs the same
  context through either tool.

- Eight days, one machine, Claude Code only. Codex and OpenCode work is not
  in this corpus, as before.
- Shares are measured in characters of transcript content. The owner's
  `/context` reading for a live session (37%) agrees with the corpus figure
  (38%), which is the calibration that matters.
- Measurement scripts are kept in `studies/context-economy/`.
- Command classification is first-match by regex; a pipeline that reads a
  file and greps it is counted as a file read.

## Decision

- Keep outctl killed. Do not reopen the projection thesis; the harness now
  ships the mechanism and the bytes it would act on are not the bytes that
  fill context.
- Archive control verified working; delete the remote copy of
  `feat/claude-session-archive` when convenient.
- Re-run this measurement only if a harness without native spooling becomes
  the primary one.
