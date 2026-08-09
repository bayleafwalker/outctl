from __future__ import annotations

from copy import deepcopy

import pytest

from outctl.ux import UxCompileError, _canonical_digest, compile_ux_evidence


def _protocol() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "vuoro.outctl.ux-task-protocol/v1",
        "protocol_id": "operations-v1",
        "protocol_digest": "",
        "minimum_turns": 2,
    }
    value["protocol_digest"] = _canonical_digest(value, omit="protocol_digest")
    return value


def _observations(protocol: dict[str, object]) -> dict[str, object]:
    value: dict[str, object] = {
        "task_protocol_digest": protocol["protocol_digest"],
        "observation_digest": "",
        "session_id": "private-session-id",
        "turns": [
            {
                "logical_commands": 2,
                "cluster_calls": 2,
                "retrievals": 1,
                "retrievals_contributing_to_findings": 1,
                "reruns_avoided": 1,
                "findings": 1,
                "checks": 1,
                "evidence_refs": ["outctl://capture/abc/manifest/sha256/" + "a" * 64],
                "bypasses": [],
            },
            {
                "logical_commands": 1,
                "cluster_calls": 1,
                "retrievals": 0,
                "retrievals_contributing_to_findings": 0,
                "reruns_avoided": 0,
                "findings": 0,
                "checks": 1,
                "evidence_refs": ["artifact:sha256:" + "b" * 64],
                "bypasses": ["small-output"],
            },
        ],
        "quality_preserved": True,
        "additional_critical_misses": 0,
        "generated_at": "2026-08-09T02:00:00Z",
    }
    value["observation_digest"] = _canonical_digest(value, omit="observation_digest")
    return value


def test_compile_ux_evidence_binds_digests_and_aggregates_turns() -> None:
    protocol = _protocol()
    result = compile_ux_evidence(protocol, _observations(protocol))
    assert result["turns"] == 2
    assert result["retrievals_contributing_to_findings"] == 1
    assert result["reruns_avoided"] == 1
    assert result["bypasses"] == [{"reason": "small-output", "count": 1}]
    assert "private-session-id" not in str(result)


def test_ux_compiler_rejects_digest_drift() -> None:
    protocol = _protocol()
    observations = _observations(protocol)
    observations["quality_preserved"] = False
    with pytest.raises(UxCompileError, match="observation digest"):
        compile_ux_evidence(protocol, observations)


def test_ux_compiler_rejects_uncited_findings() -> None:
    protocol = _protocol()
    observations = deepcopy(_observations(protocol))
    observations["turns"][0]["evidence_refs"] = []  # type: ignore[index]
    observations["observation_digest"] = _canonical_digest(observations, omit="observation_digest")
    with pytest.raises(UxCompileError, match="uncited"):
        compile_ux_evidence(protocol, observations)
