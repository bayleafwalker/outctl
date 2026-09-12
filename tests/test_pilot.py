from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

import outctl.pilot as pilot
from outctl.pilot import (
    CommandApprovalPolicy,
    PilotError,
    PilotReportError,
    parse_app_server_token_usage,
    parse_codex_jsonl,
    review_verdict,
    smoke,
    validate_app_server_schema,
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


def test_approval_canary_uses_disposable_safe_corpus(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class FakeApproval:
        def assert_complete(self) -> None:
            seen["complete"] = True

    def fake_run_app_server_turn(
        **kwargs: object,
    ) -> tuple[str, object, FakeApproval, dict[str, str]]:
        seen.update(kwargs)
        return "thread", object(), FakeApproval(), {
            "health_conclusion": "complete",
            "evidence_statement": "four commands",
            "retrieval_statement": "none",
        }

    monkeypatch.setattr(pilot, "_outctl_capability", lambda _: Path("/tmp/outctl"))
    monkeypatch.setattr(pilot, "_app_server_token_capability", lambda: "codex-cli test")
    monkeypatch.setattr(pilot, "_copy_auth", lambda *_: None)
    monkeypatch.setattr(pilot, "run_app_server_turn", fake_run_app_server_turn)

    result = pilot.approval_canary()

    assert result == {
        "status": "ok",
        "canary": "command-approval-and-completion",
        "command_completions": 4,
        "codex_version": "codex-cli test",
    }
    assert seen["session"] == "B"
    assert seen["corpus"] == tuple(("printf", f"outctl-canary-{item}") for item in range(1, 5))
    assert seen["complete"] is True


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
        (
            lambda value: value["sessions"]["A"]["usage"].pop("cache_write_tokens"),
            "telemetry-incomplete",
        ),
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
    assert "outctl run --mode enforce" in guidance
    assert "outctl run --mode enforce" in skill
    assert not (guided / "rules" / "kubectl.rules").exists()
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


def test_app_server_token_usage_is_complete_and_does_not_double_count_cache() -> None:
    event = {
        "method": "thread/tokenUsage/updated",
        "params": {
            "threadId": "a",
            "turnId": "turn-a",
            "tokenUsage": {
                "total": {
                    "inputTokens": 100,
                    "cachedInputTokens": 70,
                    "cacheWriteInputTokens": 10,
                    "outputTokens": 25,
                    "reasoningOutputTokens": 5,
                    "totalTokens": 125,
                }
            },
        },
    }
    usage = parse_app_server_token_usage(event, "a")
    assert usage.model_context_memory == 100
    assert usage.aggregate_cache_tokens == 80
    assert usage.report_fields()["reported_cost"] is None
    assert usage.report_fields()["cost_telemetry_status"] == "provider_unavailable"


@pytest.mark.parametrize(
    "event",
    [
        {"method": "thread/tokenUsage/updated", "params": {"threadId": "other"}},
        {"method": "other", "params": {}},
        {
            "method": "thread/tokenUsage/updated",
            "params": {"threadId": "a", "tokenUsage": {"total": {}}},
        },
    ],
)
def test_app_server_token_usage_rejects_incomplete_or_mixed_thread(event: object) -> None:
    with pytest.raises(PilotError):
        parse_app_server_token_usage(event, "a")


def test_app_server_schema_requires_all_token_fields(tmp_path: Path) -> None:
    schema = {
        "definitions": {
            "ThreadTokenUsageUpdatedNotification": {},
            "TokenUsageBreakdown": {
                "properties": {
                    "inputTokens": {},
                    "cachedInputTokens": {},
                    "cacheWriteInputTokens": {},
                    "outputTokens": {},
                    "reasoningOutputTokens": {},
                    "totalTokens": {},
                }
            },
        }
    }
    path = tmp_path / "schema.json"
    path.write_text(json.dumps(schema))
    validate_app_server_schema(path)
    schema["definitions"]["TokenUsageBreakdown"]["properties"].pop("cacheWriteInputTokens")
    path.write_text(json.dumps(schema))
    with pytest.raises(PilotError, match="required token fields"):
        validate_app_server_schema(path)


def _approval_params(command: str, item_id: str = "item") -> dict[str, str]:
    return {
        "threadId": "thread",
        "turnId": "turn",
        "cwd": str(Path("/tmp").resolve()),
        "itemId": item_id,
        "command": command,
    }


def test_app_server_approval_allows_only_exact_control_corpus(tmp_path: Path) -> None:
    corpus = (("kubectl", "get", "pods", "-A"),) * 4
    # The actual pilot corpus is distinct; exercise the constructor's fail-closed
    # duplicate check before testing an independently spelled four-route corpus.
    with pytest.raises(PilotError, match="distinct"):
        CommandApprovalPolicy.for_session(
            session="B", thread_id="thread", turn_id="turn", cwd=Path("/tmp"), corpus=corpus,
            spool_root=tmp_path
        )
    entries = tuple(
        ("kubectl", "get", resource)
        for resource in ("nodes", "pods", "events", "deployments")
    )
    policy = CommandApprovalPolicy.for_session(
        session="B", thread_id="thread", turn_id="turn", cwd=Path("/tmp"), corpus=entries,
        spool_root=tmp_path
    )
    assert policy.decision(_approval_params(shlex.join(entries[0]), "item-0")) == "accept"
    assert policy.decision(_approval_params(shlex.join(entries[1]), "too-early")) == "decline"
    policy.record_completion(
        {"threadId": "thread", "turnId": "turn", "item": {
            "id": "item-0", "type": "commandExecution", "status": "completed",
            "exitCode": 0, "command": shlex.join(entries[0])}}
    )
    for number, argv in enumerate(entries[1:], start=1):
        assert policy.decision(_approval_params(shlex.join(argv), f"item-{number}")) == "accept"
        policy.record_completion(
            {"threadId": "thread", "turnId": "turn", "item": {
                "id": f"item-{number}", "type": "commandExecution", "status": "completed",
                "exitCode": 0, "command": shlex.join(argv)}}
        )
    assert policy.decision(_approval_params(shlex.join(entries[0]), "extra")) == "decline"
    assert policy.decision(_approval_params("kubectl get pods -A; id", "shell")) == "decline"
    assert policy.decision(_approval_params("sh -c 'kubectl get pods'", "shell-2")) == "decline"
    assert (
        policy.decision({"threadId": "other", "turnId": "turn", "command": "kubectl get pods"})
        == "decline"
    )
    policy.assert_complete()


def test_app_server_approval_requires_existing_capture_for_one_guided_retrieval(
    tmp_path: Path,
) -> None:
    entries = tuple(
        ("kubectl", "get", resource)
        for resource in ("nodes", "pods", "events", "deployments")
    )
    policy = CommandApprovalPolicy.for_session(
        session="A", thread_id="thread", turn_id="turn", cwd=Path("/tmp"), corpus=entries,
        spool_root=tmp_path
    )
    wrapped = policy.corpus[0]
    assert wrapped[:7] == (
        "outctl", "run", "--mode", "enforce", "--spool-root", str(tmp_path), "--"
    )
    for number, argv in enumerate(policy.corpus):
        assert policy.decision(_approval_params(shlex.join(argv), f"item-{number}")) == "accept"
        policy.record_completion(
            {"threadId": "thread", "turnId": "turn", "item": {
                "id": f"item-{number}", "type": "commandExecution", "status": "completed",
                "exitCode": 0, "command": shlex.join(argv)}}
        )
    capture = tmp_path / "captures" / "capture-1"
    capture.mkdir(parents=True)
    # A deliberately incomplete capture is not eligible for retrieval.
    (capture / "manifest.json").write_text("{}")
    retrieval = (
        "outctl", "tail", "--spool-root", str(tmp_path), "capture-1", "stdout", "--lines", "20"
    )
    assert policy.decision(_approval_params(shlex.join(retrieval), "tail")) == "decline"


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _preflight_kubeconfig(tmp_path: Path) -> Path:
    kubeconfig = tmp_path / "readonly.kubeconfig"
    kubeconfig.write_text("apiVersion: v1\nkind: Config\n")
    return kubeconfig


def test_preflight_reports_unreachable_api_as_transport_not_rbac(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable API must not be reported as a missing RBAC grant.

    Regression: the sandbox denied egress to the API, every can-i returned a
    non-zero exit with empty stdout, and the launcher blamed the read-only
    role.  That sends the operator to widen a deliberately minimal ClusterRole
    to fix a local network fault.
    """

    def fake_run(argv: list[str], **_: object) -> _FakeCompleted:
        if "current-context" in argv:
            return _FakeCompleted(0, stdout="pilot\n")
        return _FakeCompleted(
            1, stderr="dial tcp 192.168.20.10:6443: connect: operation not permitted"
        )

    monkeypatch.setattr(pilot.subprocess, "run", fake_run)
    with pytest.raises(PilotError) as excinfo:
        pilot._preflight(_preflight_kubeconfig(tmp_path), "pilot", "gatus")
    message = str(excinfo.value)
    assert "could not reach the API" in message
    assert "RBAC preflight failed" not in message


def test_preflight_still_reports_a_genuine_denial_as_rbac(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """kubectl exits 1 on a real "no", which must stay an RBAC finding."""

    def fake_run(argv: list[str], **_: object) -> _FakeCompleted:
        if "current-context" in argv:
            return _FakeCompleted(0, stdout="pilot\n")
        if "nodes" in argv:
            return _FakeCompleted(1, stdout="no\n")
        return _FakeCompleted(0, stdout="yes\n")

    monkeypatch.setattr(pilot.subprocess, "run", fake_run)
    with pytest.raises(PilotError, match="read-only RBAC preflight failed for get nodes"):
        pilot._preflight(_preflight_kubeconfig(tmp_path), "pilot", "gatus")
