"""Raw-free model/tool topology and follow-up characterization.

Codex JSONL does not currently expose every internal model invocation.  This
module therefore reports the observable lower-level topology: command items,
concurrent command waves, visible agent messages, and follow-up commands that
can be classified from their command text and preceding bounded return.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

_OMISSION_MARKERS = ("[... output omitted ...]", "[omitted]", "[...]")
_CAPTURE_ID = re.compile(r"(?:capture_id:\s*|outctl://capture/)([0-9a-f]{16,})")
_HEALTH_NEGATIVE_TERMS = frozenset(
    {"pending", "crashloopbackoff", "imagepullbackoff", "oomkilled", "error"}
)
_RETRIEVAL_NAMES = frozenset({"inspect", "slice", "tail", "search", "search-many"})


@dataclass(frozen=True)
class FollowUpClassification:
    """A raw-free explanation of one follow-up-shaped command."""

    command_index: int
    command_sha256: str
    kind: str
    reason: str
    related_capture_id: str | None
    needed_for_task: str
    fact_available_before_call: str
    projection_induced: bool
    could_initial_projection_have_answered: bool | None
    repeated_original_command: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InteractionTelemetry:
    """Observable interaction topology without command text or output."""

    turn_count: int
    observable_agent_message_count: int
    model_invocation_count: int | None
    model_invocation_count_source: str
    command_count: int
    serial_tool_round_count: int
    commands_per_round: tuple[int, ...]
    parallel_round_count: int
    max_parallelism: int
    sequential_model_tool_boundaries: int
    repeated_command_count: int
    follow_up_count: int
    follow_up_reason_counts: dict[str, int]
    follow_ups: tuple[FollowUpClassification, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["commands_per_round"] = list(self.commands_per_round)
        result["follow_ups"] = [item.to_dict() for item in self.follow_ups]
        return result


def _command_item(event: Mapping[str, Any]) -> Mapping[str, Any] | None:
    item = event.get("item")
    if not isinstance(item, Mapping) or item.get("type") != "command_execution":
        return None
    return item


def _command_text(item: Mapping[str, Any]) -> str:
    value = item.get("command")
    return value if isinstance(value, str) else ""


def _command_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _capture_ids(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(match.group(1) for match in _CAPTURE_ID.finditer(text)))


def _retrieval_name(command: str) -> str | None:
    folded = command.casefold()
    for name in sorted(_RETRIEVAL_NAMES, key=len, reverse=True):
        if re.search(rf"(?:outctl-health|outctl_kubectl_router\.py)\s+{re.escape(name)}\b", folded):
            return name
    return None


def _literal_terms(command: str) -> set[str]:
    folded = command.casefold()
    return {term for term in _HEALTH_NEGATIVE_TERMS if term in folded}


def _is_discovery(command: str) -> bool:
    folded = command.casefold()
    return (
        "--help" in folded
        or re.search(r"(?:^|\s)(?:help|-h)(?:\s|$)", folded) is not None
        or "skill.md" in folded
        or ".agents/skills" in folded
    )


def _round_metrics(events: Sequence[Mapping[str, Any]]) -> tuple[int, tuple[int, ...], int, int]:
    """Group command items into observable concurrent waves.

    A new wave begins when a command starts with no active command.  This is
    deliberately conservative: the Codex event stream does not expose model
    request IDs, so a wave is the strongest portable proxy for a serial
    model/tool decision boundary.
    """

    active: set[str] = set()
    rounds: list[int] = []
    started_without_completion: set[str] = set()
    for event in events:
        event_type = event.get("type")
        item = _command_item(event)
        if item is None:
            continue
        item_id = item.get("id")
        identifier = (
            item_id
            if isinstance(item_id, str)
            else f"anonymous-{len(started_without_completion)}"
        )
        if event_type == "item.started":
            if not active:
                rounds.append(0)
            rounds[-1] += 1
            active.add(identifier)
            started_without_completion.add(identifier)
        elif event_type == "item.completed":
            if identifier not in started_without_completion:
                if not active:
                    rounds.append(0)
                if rounds[-1] == 0:
                    rounds[-1] = 1
            active.discard(identifier)
    parallel = sum(count > 1 for count in rounds)
    return len(rounds), tuple(rounds), parallel, max(rounds, default=0)


def _classify_follow_ups(
    command_items: Sequence[tuple[int, Mapping[str, Any]]],
) -> tuple[FollowUpClassification, ...]:
    prior_hashes: set[str] = set()
    prior_outputs: list[str] = []
    prior_capture_ids: list[str] = []
    result: list[FollowUpClassification] = []
    for command_index, item in command_items:
        command = _command_text(item)
        command_hash = _command_hash(command)
        output = item.get("aggregated_output")
        output_text = output if isinstance(output, str) else ""
        previous_output = prior_outputs[-1] if prior_outputs else ""
        previous_omitted = any(marker in previous_output for marker in _OMISSION_MARKERS)
        retrieval = _retrieval_name(command)
        discovery = _is_discovery(command)
        repeated = command_hash in prior_hashes
        if retrieval is None and not discovery and not repeated:
            prior_hashes.add(command_hash)
            prior_outputs.append(output_text)
            prior_capture_ids.extend(_capture_ids(output_text))
            continue

        if discovery:
            kind, reason = "interface_discovery", "interface_discovery"
            needed, available, induced, answerable = "no", "yes", False, True
            related = None
        elif repeated:
            kind, reason = "repeated_command", "repeated_original_command"
            needed, available, induced, answerable = "unknown", "ambiguous", False, None
            related = None
        elif retrieval is not None:
            terms = _literal_terms(command)
            if terms and terms <= {"pending", "crashloopbackoff", "imagepullbackoff"}:
                reason = "confirm_absence"
                needed, available, induced, answerable = (
                    "likely",
                    "ambiguous",
                    previous_omitted,
                    True,
                )
            elif terms:
                reason = "completeness_uncertainty"
                needed, available, induced, answerable = (
                    "likely",
                    "ambiguous",
                    previous_omitted,
                    True,
                )
            else:
                reason = "raw_seeking"
                needed, available, induced, answerable = "unknown", "no", previous_omitted, None
            kind = "retrieval"
            command_captures = _capture_ids(command)
            related = next(
                (capture_id for capture_id in command_captures if capture_id in prior_capture_ids),
                command_captures[0]
                if command_captures
                else (prior_capture_ids[-1] if prior_capture_ids else None),
            )
        else:
            kind, reason = "follow_up", "other"
            needed, available, induced, answerable = "unknown", "ambiguous", previous_omitted, None
            related = None

        result.append(
            FollowUpClassification(
                command_index=command_index,
                command_sha256=command_hash,
                kind=kind,
                reason=reason,
                related_capture_id=related,
                needed_for_task=needed,
                fact_available_before_call=available,
                projection_induced=induced,
                could_initial_projection_have_answered=answerable,
                repeated_original_command=repeated,
            )
        )
        prior_hashes.add(command_hash)
        prior_outputs.append(output_text)
        prior_capture_ids.extend(_capture_ids(output_text))
    return tuple(result)


def analyze_events(events: Sequence[Mapping[str, Any]]) -> InteractionTelemetry:
    """Derive interaction topology and raw-free follow-up classifications."""

    command_items = [
        (index, item)
        for index, event in enumerate(events, start=1)
        if event.get("type") == "item.completed" and (item := _command_item(event)) is not None
    ]
    rounds, commands_per_round, parallel_rounds, max_parallelism = _round_metrics(events)
    follow_ups = _classify_follow_ups(command_items)
    reason_counts: dict[str, int] = {}
    for follow_up in follow_ups:
        reason_counts[follow_up.reason] = reason_counts.get(follow_up.reason, 0) + 1
    turn_count = sum(event.get("type") == "turn.started" for event in events)
    agent_messages = sum(
        event.get("type") == "item.completed"
        and isinstance(event.get("item"), Mapping)
        and event["item"].get("type") == "agent_message"
        for event in events
    )
    return InteractionTelemetry(
        turn_count=turn_count,
        observable_agent_message_count=agent_messages,
        model_invocation_count=None,
        model_invocation_count_source="codex_jsonl_does_not_expose_internal_model_invocations",
        command_count=len(command_items),
        serial_tool_round_count=rounds,
        commands_per_round=commands_per_round,
        parallel_round_count=parallel_rounds,
        max_parallelism=max_parallelism,
        sequential_model_tool_boundaries=max(0, rounds - 1),
        repeated_command_count=sum(item.kind == "repeated_command" for item in follow_ups),
        follow_up_count=sum(item.kind != "repeated_command" for item in follow_ups),
        follow_up_reason_counts=reason_counts,
        follow_ups=follow_ups,
    )
