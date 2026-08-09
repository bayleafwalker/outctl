from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "acceptance/codex_appservice_ab/kubectl_replay.py"
SPEC = importlib.util.spec_from_file_location("kubectl_replay", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ReplayError, _load, replay = MODULE.ReplayError, MODULE._load, MODULE.replay


def test_replay_is_exact_and_offline(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({"nodes": [{"name": "n1", "ready": False}]}))
    digest = "sha256:" + hashlib.sha256(fixture.read_bytes()).hexdigest()
    value = _load(fixture, digest)
    assert replay(value, ["get", "nodes", "-o", "wide"])["items"][0]["name"] == "n1"
    with pytest.raises(ReplayError, match="outside"):
        replay(value, ["get", "secrets", "-A", "-o", "json"])


def test_replay_rejects_fixture_drift(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.json"
    fixture.write_text("{}")
    with pytest.raises(ReplayError, match="digest mismatch"):
        _load(fixture, "sha256:" + "1" * 64)


@pytest.mark.parametrize(
    "command",
    [
        ["version", "-o", "json"],
        ["get", "nodes", "-o", "wide"],
        ["get", "pods", "-A", "-o", "wide"],
        ["-n", "flux-system", "get", "pods", "-o", "wide"],
        ["-n", "gatus", "get", "deployments,persistentvolumeclaims"],
        ["-n", "gatus", "get", "events", "--sort-by=.lastTimestamp"],
    ],
)
def test_replay_accepts_each_frozen_prompt_command(command: list[str]) -> None:
    assert isinstance(replay({}, command), dict)
