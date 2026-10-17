# Devbox implementation setup

> **Historical.** Outctl's product thesis and W0-W8 roadmap were retired on
> 2026-08-16. Do not use this setup to start feature work or select new sprints.
> The commands below are retained only to reproduce the frozen source checks.

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
python /projects/dev/agentops/scripts/validate_verification_artifacts.py --root .
```

If the repository is already cloned, inspect its worktree before pulling. Do
not overwrite divergent or uncommitted work. The devbox host has allowlisted
egress and no cluster authority; Phase 1 requires neither cluster access nor
production credentials.

## Autonomous pass contract

This historical implementation workflow is closed. Any narrowly authorized
maintenance correction should state its bounded source-only purpose, preserve
the kill decision, run relevant repository checks, and leave a handoff that
separates source evidence from installed or runtime qualification.

Routine test captures are `session-local` or `host-persistent` depending on
their configured spool. They are never `durable-authoritative`.

