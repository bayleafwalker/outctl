# Devbox implementation setup

`/projects/dev` is host-local. The workstation repository and devbox-vm clone
must be synchronized through Git; copying this path does not synchronize them.

## Bootstrap on devbox-vm

```bash
ssh devbox-agent
tmux new-session -s outctl
cd /projects/dev
git clone https://github.com/bayleafwalker/outctl.git
cd outctl
uv sync --all-extras --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
python /projects/dev/agentops/templates/dispatch/scripts/validate_verification_artifacts.py --root .
```

If the repository is already cloned, inspect its worktree before pulling. Do
not overwrite divergent or uncommitted work. The devbox host has allowlisted
egress and no cluster authority; Phase 1 requires neither cluster access nor
production credentials.

## Autonomous pass contract

1. Read `AGENTS.md`, `docs/IMPLEMENTATION_PLAN.md`, and applicable risk surfaces.
2. Select exactly one ready pass or smaller sprint item.
3. Freeze interfaces and falsifying tests before mechanical implementation.
4. Use disposable worktrees under `/tmp/outctl-hybrid/worktrees` for bounded workers.
5. Run the registered gate cold in the exact candidate commit.
6. Commit locally and leave a handoff with source host, path, commit, checks,
   deviations, and evidence classification.
7. Do not push, mutate workflow authorities, publish packages, or access
   production unless the task separately grants that authority.

Routine test captures are `session-local` or `host-persistent` depending on
their configured spool. They are never `durable-authoritative`.

