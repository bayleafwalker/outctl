"""Offline replay helpers for interaction-ergonomics characterization."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from interaction import analyze_events


def load_replay_scenarios(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or value.get("schema_version") != "outctl.codex-ab.replay/v1":
        raise ValueError("invalid replay scenario document")
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("replay scenario document lacks scenarios")
    result: list[dict[str, Any]] = []
    for scenario in scenarios:
        if not isinstance(scenario, dict) or not isinstance(scenario.get("id"), str):
            raise ValueError("replay scenario must have a string id")
        if not isinstance(scenario.get("events"), list):
            raise ValueError("replay scenario must have events")
        result.append(scenario)
    return result


def replay_scenario(scenario: Mapping[str, Any]) -> dict[str, Any]:
    events = scenario.get("events")
    if not isinstance(events, list) or not all(isinstance(event, Mapping) for event in events):
        raise ValueError("replay scenario events must be objects")
    return analyze_events(events).to_dict()
