# outctl agent guidance

`outctl` captures command output, produces deterministic bounded projections,
and retrieves omitted evidence. It does not own command scheduling, work state,
action lifecycle, audit judgments, curated knowledge, or remote execution.

## Read first

Before changing behavior, read:

1. `docs/DESIGN.md`
2. `docs/THREAT-MODEL.md`
3. `acceptance/SCENARIOS.md`
4. `IMPLEMENTATION_HANDOFF.md`
5. `outctl.dispatch.json` and the applicable risk surfaces

## Closed boundaries

- Execute argv directly. Never introduce an implicit shell.
- Never buffer complete command output in memory.
- Drain stdout and stderr concurrently even after capture quota exhaustion.
- Keep command status distinct from capture/projection status.
- Raw capture bytes never enter Git, sprintctl, kctl, auditctl, or ordinary
  model-facing output.
- Raw spool directories are mode `0700`; capture files are mode `0600`.
- Projection is deterministic and model-free in Phase 1.
- Retrieval never reruns the wrapped command.
- Do not add a daemon, remote executor, database, PTY, or cluster dependency in
  Phase 1.

## Implementation order

Work in the four slices defined in `docs/IMPLEMENTATION_PLAN.md`. Do not begin a
later slice until the preceding slice's gates pass. Each pass must leave the
repository runnable and commit only its own scoped changes.

## Verification

Run targeted tests first, then:

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
python /projects/dev/agentops/templates/dispatch/scripts/validate_verification_artifacts.py --root .
```

The AgentOps validator is required on hosts where `/projects/dev/agentops` is
present. CI validates the repository-local gates independently.

## Git and external authority

Unsupervised implementation passes may edit and commit within this repository.
They may not push, open or merge pull requests, mutate sprint/action/audit
state, publish packages, or access production systems unless a task explicitly
grants that authority.

<!-- agentops-project-pointer:start -->
See `.agents/project.generated.md` for cross-repo project context (agentops-managed; do not hand-edit).
<!-- agentops-project-pointer:end -->

<!-- agentops-environment-pointer:start -->
See `.agents/environment.generated.md` for the active Vuoro environment's constraints and runbooks (agentops-managed; do not hand-edit).
<!-- agentops-environment-pointer:end -->
