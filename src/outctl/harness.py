"""Provider-neutral N-arm launch planning and grouped execution.

This is deliberately independent of Codex, Kubernetes, and outctl capture.
The old acceptance runner can remain a compatibility client while new test
handlers and runners use this spine.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from outctl.contracts import (
    MAX_PROTOCOL_CANONICAL_BYTES,
    ContractValidationError,
    validate_contract,
)
from outctl.scenarios import MaterializedScenario, ScenarioHandler


class LaunchPlanError(ValueError):
    """Raised when a sealed launch cannot be planned safely."""


@dataclass(frozen=True)
class Arm:
    arm_id: str
    capture: str
    projection: str
    tool_surface: str
    runner: str | None = None


@dataclass(frozen=True)
class Session:
    session_id: str
    scenario_id: str
    arm_id: str
    replicate: int
    start_group: str
    start_order: int


@dataclass(frozen=True)
class StartGroup:
    group_id: str
    sessions: tuple[Session, ...]


@dataclass(frozen=True)
class LaunchPlan:
    protocol_digest: str
    sessions: tuple[Session, ...]
    groups: tuple[StartGroup, ...]
    estimated_sessions: int
    estimated_credits: float
    max_concurrent_sessions: int | None
    max_sessions: int | None
    max_credits: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol_digest": self.protocol_digest,
            "estimated_sessions": self.estimated_sessions,
            "estimated_credits": self.estimated_credits,
            "limits": {
                "max_sessions": self.max_sessions,
                "max_concurrent_sessions": self.max_concurrent_sessions,
                "max_credits": self.max_credits,
            },
            "sessions": [
                {
                    "session_id": item.session_id,
                    "scenario_id": item.scenario_id,
                    "arm_id": item.arm_id,
                    "replicate": item.replicate,
                    "start_group": item.start_group,
                    "start_order": item.start_order,
                }
                for item in self.sessions
            ],
        }


type RunResult = Mapping[str, Any]
type SessionRunner = Callable[[Session], RunResult]
type MaterializedSessionRunner = Callable[[Session, MaterializedScenario], RunResult]


def _canonical_digest(value: Mapping[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "protocol_digest"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _limits(protocol: Mapping[str, Any]) -> tuple[int | None, int | None, float | None]:
    raw = protocol.get("limits")
    if not isinstance(raw, Mapping):
        raise LaunchPlanError("v3 protocol limits are required")

    def integer(name: str) -> int | None:
        value = raw.get(name)
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise LaunchPlanError(f"limits.{name} must be a positive integer or null")
        return value

    max_credits = raw.get("max_credits")
    if max_credits is not None and (
        not isinstance(max_credits, (int, float))
        or isinstance(max_credits, bool)
        or max_credits < 0
    ):
        raise LaunchPlanError("limits.max_credits must be a non-negative number or null")
    return (
        integer("max_sessions"),
        integer("max_concurrent_sessions"),
        float(max_credits) if max_credits is not None else None,
    )


def _arms(matrix: Mapping[str, Any]) -> tuple[Arm, ...]:
    raw = matrix.get("arms")
    if not isinstance(raw, list) or not raw:
        raise LaunchPlanError("arm matrix must contain at least one arm")
    result: list[Arm] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise LaunchPlanError("arm matrix arm must be an object")
        arm_id, capture, projection, tool_surface = (
            item.get("arm_id"),
            item.get("capture"),
            item.get("projection"),
            item.get("tool_surface"),
        )
        if not all(
            isinstance(value, str) and value
            for value in (arm_id, capture, projection, tool_surface)
        ):
            raise LaunchPlanError("arm matrix contains an incomplete arm")
        assert isinstance(arm_id, str)
        assert isinstance(capture, str)
        assert isinstance(projection, str)
        assert isinstance(tool_surface, str)
        if arm_id in seen:
            raise LaunchPlanError(f"duplicate arm ID: {arm_id}")
        seen.add(arm_id)
        runner = item.get("runner")
        result.append(
            Arm(
                arm_id,
                capture,
                projection,
                tool_surface,
                runner if isinstance(runner, str) else None,
            )
        )
    return tuple(result)


def _validate_inputs(
    protocol: Mapping[str, Any], suite: Mapping[str, Any], matrix: Mapping[str, Any]
) -> tuple[tuple[Mapping[str, Any], ...], tuple[Arm, ...]]:
    try:
        checked_protocol = validate_contract("study-protocol", protocol)
        checked_suite = validate_contract("scenario-suite", suite)
        checked_matrix = validate_contract("arm-matrix", matrix)
    except ContractValidationError as exc:
        raise LaunchPlanError(str(exc)) from exc
    if checked_protocol.get("schema_version") != "vuoro.outctl.study-protocol/v3":
        raise LaunchPlanError("N-arm planning requires study-protocol/v3")
    if checked_protocol.get("scenario_suite_digest") != checked_suite.get("suite_digest"):
        raise LaunchPlanError("protocol does not bind the supplied scenario suite")
    if checked_protocol.get("arm_matrix_digest") != checked_matrix.get("matrix_digest"):
        raise LaunchPlanError("protocol does not bind the supplied arm matrix")
    matrix_arms = _arms(checked_matrix)
    if checked_protocol.get("arm_ids") != [arm.arm_id for arm in matrix_arms]:
        raise LaunchPlanError("protocol arm_ids do not match the sealed arm matrix")
    if checked_protocol.get("protocol_digest") != _canonical_digest(checked_protocol):
        raise LaunchPlanError("protocol digest does not bind canonical bytes")
    encoded = json.dumps(
        {key: item for key, item in checked_protocol.items() if key != "protocol_digest"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    if len(encoded) > MAX_PROTOCOL_CANONICAL_BYTES:
        raise LaunchPlanError("protocol exceeds the v3 initial canonical byte limit")
    scenarios = checked_suite.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise LaunchPlanError("scenario suite must contain at least one scenario")
    return tuple(item for item in scenarios if isinstance(item, Mapping)), matrix_arms


def plan_sessions(
    protocol: Mapping[str, Any],
    suite: Mapping[str, Any],
    matrix: Mapping[str, Any],
    *,
    replicate_offset: int = 0,
) -> LaunchPlan:
    """Create all N-arm sessions and start groups before any runner starts."""
    if replicate_offset < 0:
        raise LaunchPlanError("replicate_offset must be non-negative")
    scenarios, arms = _validate_inputs(protocol, suite, matrix)
    max_sessions, max_concurrent, max_credits = _limits(protocol)
    if max_concurrent is not None and max_concurrent < len(arms):
        raise LaunchPlanError("max_concurrent_sessions is smaller than one matched start group")
    replicates = protocol.get("replicates")
    if not isinstance(replicates, int) or isinstance(replicates, bool) or replicates < 1:
        raise LaunchPlanError("protocol replicates must be positive")
    total = len(scenarios) * len(arms) * replicates
    if max_sessions is not None and total > max_sessions:
        raise LaunchPlanError(f"planned session count {total} exceeds max_sessions {max_sessions}")
    per_session = protocol.get("estimated_credits_per_session", 0)
    if (
        not isinstance(per_session, (int, float))
        or isinstance(per_session, bool)
        or per_session < 0
    ):
        raise LaunchPlanError("estimated_credits_per_session must be non-negative")
    estimated_credits = float(total) * float(per_session)
    if max_credits is not None and estimated_credits > max_credits:
        raise LaunchPlanError(
            f"estimated credits {estimated_credits:g} exceeds max_credits {max_credits:g}"
        )

    seed = protocol.get("randomization_seed")
    if not isinstance(seed, int) or isinstance(seed, bool) or seed < 0:
        raise LaunchPlanError("randomization_seed must be non-negative")
    sessions: list[Session] = []
    groups: list[StartGroup] = []
    for scenario_index, scenario in enumerate(scenarios):
        scenario_id = scenario.get("scenario_id")
        if not isinstance(scenario_id, str):
            raise LaunchPlanError("scenario binding has no scenario_id")
        for replicate in range(1, replicates + 1):
            group_id = f"{scenario_id}/r{replicate + replicate_offset}"
            rotation = (seed + replicate_offset + scenario_index + replicate - 1) % len(arms)
            order = arms[rotation:] + arms[:rotation]
            group_sessions = tuple(
                Session(
                    session_id=f"{group_id}/{arm.arm_id}",
                    scenario_id=scenario_id,
                    arm_id=arm.arm_id,
                    replicate=replicate + replicate_offset,
                    start_group=group_id,
                    start_order=start_order,
                )
                for start_order, arm in enumerate(order)
            )
            sessions.extend(group_sessions)
            groups.append(StartGroup(group_id, group_sessions))
    return LaunchPlan(
        str(protocol["protocol_digest"]),
        tuple(sessions),
        tuple(groups),
        total,
        estimated_credits,
        max_concurrent,
        max_sessions,
        max_credits,
    )


def execute_plan(plan: LaunchPlan, runner: SessionRunner) -> tuple[RunResult, ...]:
    """Run each matched group concurrently using a group-sized barrier."""
    results: dict[str, RunResult] = {}
    errors: dict[str, BaseException] = {}
    for group in plan.groups:
        barrier = threading.Barrier(len(group.sessions) + 1)
        lock = threading.Lock()

        def worker(
            session: Session,
            barrier: threading.Barrier = barrier,
            lock: threading.Lock = lock,
        ) -> None:
            try:
                barrier.wait()
                value = runner(session)
                with lock:
                    results[session.session_id] = value
            except BaseException as exc:  # re-raised in the coordinator thread
                with lock:
                    errors[session.session_id] = exc

        threads = [threading.Thread(target=worker, args=(session,)) for session in group.sessions]
        for thread in threads:
            thread.start()
        try:
            barrier.wait()
        except threading.BrokenBarrierError as exc:
            for thread in threads:
                thread.join()
            raise LaunchPlanError(f"start group {group.group_id} failed") from exc
        for thread in threads:
            thread.join()
        if errors:
            session_id, error = next(iter(errors.items()))
            raise LaunchPlanError(f"session {session_id} failed: {error}") from error
    return tuple(results[session.session_id] for session in plan.sessions)


class Launcher:
    """Reusable plan-then-execute facade for test and production runners."""

    def plan(
        self,
        protocol: Mapping[str, Any],
        suite: Mapping[str, Any],
        matrix: Mapping[str, Any],
        *,
        replicate_offset: int = 0,
    ) -> LaunchPlan:
        return plan_sessions(protocol, suite, matrix, replicate_offset=replicate_offset)

    def execute(self, plan: LaunchPlan, runner: SessionRunner) -> tuple[RunResult, ...]:
        return execute_plan(plan, runner)

    def launch(
        self,
        protocol: Mapping[str, Any],
        suite: Mapping[str, Any],
        matrix: Mapping[str, Any],
        runner: SessionRunner,
        *,
        replicate_offset: int = 0,
    ) -> tuple[RunResult, ...]:
        return self.execute(
            self.plan(protocol, suite, matrix, replicate_offset=replicate_offset), runner
        )

    def launch_with_handler(
        self,
        protocol: Mapping[str, Any],
        suite: Mapping[str, Any],
        matrix: Mapping[str, Any],
        handler: ScenarioHandler,
        repository_root: Path,
        materialize_root: Path,
        runner: MaterializedSessionRunner,
        *,
        replicate_offset: int = 0,
    ) -> tuple[RunResult, ...]:
        """Resolve packages before launch and materialize one per session."""
        plan = self.plan(protocol, suite, matrix, replicate_offset=replicate_offset)
        bindings = {
            str(binding["scenario_id"]): binding
            for binding in suite["scenarios"]
            if isinstance(binding, Mapping) and isinstance(binding.get("scenario_id"), str)
        }
        resolved = {
            scenario_id: handler.resolve(binding, repository_root)
            for scenario_id, binding in bindings.items()
        }

        def run(session: Session) -> RunResult:
            scenario = resolved.get(session.scenario_id)
            if scenario is None:
                raise LaunchPlanError(f"no resolved scenario for {session.scenario_id}")
            target = materialize_root / session.session_id.replace("/", "__")
            materialized = handler.materialize(scenario, target)
            try:
                return runner(session, materialized)
            finally:
                handler.teardown(materialized)

        return self.execute(plan, run)


__all__ = [
    "Arm",
    "LaunchPlan",
    "LaunchPlanError",
    "Launcher",
    "Session",
    "StartGroup",
    "execute_plan",
    "plan_sessions",
]
