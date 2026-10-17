# outctl agent guidance

`outctl` captures command output, produces deterministic bounded projections,
and retrieves omitted evidence. It does not own command scheduling, work state,
action lifecycle, audit judgments, curated knowledge, or remote execution.

The product thesis was killed on 2026-08-16. Treat this repository as a frozen
discovery artifact under maintenance; do not resume product or roadmap work.
See `docs/DISCOVERY_KILL_2026-08-16.md` before changing the retained source.

## Read first

Before changing behavior, read:

1. `docs/DESIGN.md`
2. `docs/THREAT-MODEL.md`
3. `acceptance/SCENARIOS.md`
4. `IMPLEMENTATION_HANDOFF.md`
5. The applicable risk surfaces and repository-local verification gates.

## Closed boundaries

- Execute argv directly. Never introduce an implicit shell.
- Never buffer complete command output in memory.
- Drain stdout and stderr concurrently even after capture quota exhaustion.
- Keep command status distinct from capture/projection status.
- Raw capture bytes never enter Git, sprintctl, kctl, auditctl, or ordinary
  model-facing output.
- Raw spool directories are mode `0700`; capture files are mode `0600`.
- Core projection remains deterministic and model-free in the mature MVP.
- Retrieval never reruns the wrapped command.
- Do not add a required daemon, remote executor, central database, PTY, or
  cluster dependency in the mature MVP.

## Historical implementation plans

The four slices in `docs/IMPLEMENTATION_PLAN.md` and W0-W8 in
`docs/MIGRATION_ROADMAP.md` are historical. The roadmap was retired with the
product thesis; its sequencing is not authorization to resume implementation.

## Verification

Run targeted tests first, then:

```bash
uv sync --all-extras --dev
uv run pytest
uv run ruff check .
uv run mypy src
uv build
python /projects/dev/agentops/scripts/validate_verification_artifacts.py --root .
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
