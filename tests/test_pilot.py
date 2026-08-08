from __future__ import annotations

import json
from pathlib import Path

import pytest

from outctl.pilot import (
    PilotError,
    PilotReportError,
    parse_codex_jsonl,
    review_verdict,
    smoke,
    validate_pilot_report,
    validate_report,
)

ROOT = Path(__file__).parents[1]


def report() -> dict[str, object]:
    return json.loads((ROOT / "tests" / "fixtures" / "pilot-report.json").read_text())


def test_offline_smoke_and_complete_usage() -> None:
    assert smoke() == {"status": "ok", "verdict": "continue"}
    telemetry = parse_codex_jsonl(ROOT / "tests" / "fixtures" / "pilot-A.jsonl", "A")
    assert telemetry.usage.model_context_memory == 110
    assert telemetry.usage.aggregate_cache_tokens == 15


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ('{"thread_id":"one","usage":{"input_tokens":1}}\n', "telemetry-incomplete"),
        ("not json\n", "malformed"),
        (
            '{"thread_id":"one","usage":{"input_tokens":1,"output_tokens":1,"cached_input_tokens":0,"cache_creation_input_tokens":0}}\n',
            "telemetry-incomplete",
        ),
    ],
)
def test_jsonl_parser_rejects_incomplete_or_malformed(
    tmp_path: Path, contents: str, message: str
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(contents)
    with pytest.raises(PilotError, match=message):
        parse_codex_jsonl(path, "A")


def test_jsonl_parser_rejects_mixed_sessions(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"thread_id":"one"}\n'
        '{"thread_id":"two","usage":{"input_tokens":1,"output_tokens":1,"cached_input_tokens":0,"cache_creation_input_tokens":0,"cost_usd":1}}\n'
    )
    with pytest.raises(PilotError, match="exactly one session"):
        parse_codex_jsonl(path, "A")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value["sessions"]["A"].update({"stdout": "secret"}), "raw or projection"),
        (
            lambda value: value["sessions"]["A"]["retrieval"].update({"reran_kubectl": True}),
            "retrieval proof",
        ),
        (
            lambda value: value["sessions"]["B"].update({"session_id": "pilot-guided-1"}),
            "mixed or duplicate",
        ),
        (lambda value: value["sessions"]["A"]["commands"][0]["argv"].append("delete"), "mutation"),
        (lambda value: value["sessions"]["A"]["usage"].pop("cost"), "telemetry-incomplete"),
    ],
)
def test_report_rejects_unsafe_or_incomplete_evidence(mutate: object, message: str) -> None:
    value = report()
    mutate(value)  # type: ignore[operator]
    with pytest.raises(PilotError, match=message):
        validate_report(value)  # type: ignore[arg-type]


def test_guided_bundle_and_control_are_isolated() -> None:
    guided = ROOT / "pilot" / "guided"
    guidance = (guided / "AGENTS.md").read_text()
    skill = (guided / "skills" / "outctl-health-check" / "SKILL.md").read_text()
    guard = (guided / "rules" / "kubectl.rules").read_text()
    assert "outctl run --mode enforce" in guidance
    assert "outctl run --mode enforce" in skill
    assert 'pattern=["kubectl"]' in guard
    assert (
        "outctl"
        not in "\n".join(
            path.read_text() for path in (ROOT / "pilot" / "control").rglob("*") if path.is_file()
        ).lower()
    )


def test_review_uses_health_conclusion_not_a_release_threshold() -> None:
    value = report()
    assert review_verdict(value) == "continue"
    value["sessions"]["A"]["usage"]["cache_write_tokens"] = 60  # type: ignore[index]
    assert review_verdict(value) == "continue"
    value["review"]["health_conclusion_preserved"] = False  # type: ignore[index]
    assert review_verdict(value) == "adjust"


def test_preserves_qualitative_pilot_validator() -> None:
    value = {
        "pilot": {
            "harness": "codex",
            "command_class": "appservice-health-check",
            "policy_digest": "sha256:" + "a" * 64,
        },
        "baseline": {"exposed_tokens": 900},
        "enforce": {
            "raw_tokens": 1200,
            "exposed_tokens": 300,
            "retrieved_tokens": 80,
            "retrieval_count": 1,
            "wall_time_ms": 1200,
            "wrapper_overhead_ms": 90,
        },
        "assessment": {
            "harness_native_context_management": "limited visible truncation",
            "outctl_increment": "bounded retrieval available",
            "recommendation": "continue pilot",
        },
    }
    assert validate_pilot_report(value).retrieval_count == 1
    value["stdout"] = "forbidden"
    with pytest.raises(PilotReportError, match="forbidden"):
        validate_pilot_report(value)
