# Dispatch operations findings

## Scope and evidence boundary

This record captures operational observations from the Phase 1 implementation
dispatches on 2026-08-08. It deliberately contains no raw captured command
output, secrets, or provider logs. It is not an audit finding and does not
change command, sprint, action, or audit authority.

## Observed behavior

- Initial background launches without a detached session could exit before a
  usable OpenCode session was established. Launching through `setsid` fixed
  that lifecycle issue.
- After that correction, multiple implementation and planning sessions were
  demonstrably alive: their session metadata advanced and diagnostic log volume
  grew, while their isolated worktrees remained unchanged.
- The affected sessions repeatedly read broad repository/governance material
  despite edit-first, file-scoped prompts. They did not transition to a patch
  or a concise final memo within the allotted interval.
- One planning session reached a terminal step without a usable synthesized
  answer. Process termination is therefore not evidence of a successful
  dispatch result.

## Root-cause assessment

The evidence distinguishes two failure classes:

1. **Launcher lifecycle failure.** Solved by detached launch and explicit
   session-ID tracking.
2. **Agent completion failure.** The worker entered unbounded investigation
   behavior, ignored the prompt's intended scope, and lacked a reliable
   evidence-to-synthesis transition. This is not a worktree isolation or Git
   failure: the worktrees stayed clean until coordinator changes were made.

## Required normal dispatch flow

1. Create an isolated worktree from a clean, committed base.
2. Launch detached and record the provider session ID, worktree, task scope,
   and expected changed paths.
3. Give implementation workers a short reconnaissance budget and a mandatory
   checkpoint: either a concrete diff or a concise blocker memo.
4. Poll process state, session metadata, and worktree diff on a bounded
   interval. Two implementation intervals with no diff trip the circuit
   breaker.
5. Require a final-result check in addition to process exit. A terminal
   session without a patch or memo is unsuccessful, not successful.
6. Independently review the diff and run targeted tests followed by the full
   repository gate before a scoped commit/cherry-pick.
7. Do not start a later implementation slice until the preceding slice's
   gates pass.

## Packet template

Every implementation packet must state: the base commit; exact writable paths;
explicitly excluded paths and capabilities; the one bounded behavior to build;
the required focused tests; the checkpoint interval; and the required final
report fields (changed paths, test results, remaining blockers). Planning
packets must similarly require a bounded memo and must be classified as failed
when they end without one.

## Current application

Pass 2 used this flow for isolated implementation, coordinator review, full
verification, and scoped integration. Pass 3 dispatches must retain the same
checkpoint and circuit-breaker controls.
