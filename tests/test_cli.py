from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

import outctl.capture.runner
from outctl.cli import main


def _capture(root: Path, capture_id: str = "capture-0001") -> Path:
    path = root / "captures" / capture_id
    path.mkdir(parents=True)
    stdout = b"alpha\nbeta marker\ngamma\n"
    stderr = b"warning\n"
    events = b'{"seq":0,"stream":"stdout"}\n'
    for name, data in (("stdout.raw", stdout), ("stderr.raw", stderr), ("events.ndjson", events)):
        (path / name).write_bytes(data)
        os.chmod(path / name, 0o600)
    (path / "manifest.json").write_text(
        json.dumps(
            {
                "capture_id": capture_id,
                "capture_status": "COMPLETE",
                "streams": {
                    "stdout": {"bytes": len(stdout), "sha256": hashlib.sha256(stdout).hexdigest()},
                    "stderr": {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()},
                },
                "event_index": {"events": 1, "sha256": hashlib.sha256(events).hexdigest()},
            }
        )
    )
    os.chmod(path / "manifest.json", 0o600)
    return path


def _payload(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)


def test_cli_dispatches_read_only_retrieval_without_running_a_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _capture(tmp_path)
    invoked = False

    async def fail_if_called(*args: object, **kwargs: object) -> object:
        nonlocal invoked
        invoked = True
        raise AssertionError("CLI retrieval must not run commands")

    monkeypatch.setattr(outctl.capture.runner, "capture_command", fail_if_called)
    assert main(["slice", "--spool-root", str(tmp_path), "capture-0001", "stdout", "0", "5"]) == 0
    payload = _payload(capsys)
    assert payload["status"] == "AVAILABLE"
    assert invoked is False


def test_cli_batches_literal_searches_as_one_bounded_retrieval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _capture(tmp_path)

    assert main(
        [
            "search-many",
            "--spool-root",
            str(tmp_path),
            "capture-0001",
            "stdout",
            "alpha",
            "marker",
            "missing",
        ]
    ) == 0
    payload = _payload(capsys)
    queries = payload["queries"]
    assert [len(query["matches"]) for query in queries] == [1, 1, 0]  # type: ignore[union-attr]
    events = (tmp_path / "retrieval-events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(events) == 1
    assert json.loads(events[0])["operation"] == "search-many"


def test_cli_inspect_exposes_only_bounded_outline_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _capture(tmp_path)
    assert main(["inspect", "--spool-root", str(tmp_path), "capture-0001"]) == 0
    payload = _payload(capsys)
    assert payload["outline"]["retrieval_operations"] == [  # type: ignore[index]
        "slice",
        "tail",
        "search",
        "search-many",
    ]


def test_cli_projects_binary_data_and_reports_tampering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _capture(tmp_path)
    binary = b"safe\x1b]52;clipboard\x07\xff\n"
    (path / "stdout.raw").write_bytes(binary)

    assert main(["slice", "--spool-root", str(tmp_path), "capture-0001", "stdout", "0", "100"]) == 0
    payload = _payload(capsys)
    text = payload["projection"]["text"]  # type: ignore[index]
    assert "\x1b" not in text
    assert "\\x1b" in text
    assert "\ufffd" in text

    assert main(["verify", "--spool-root", str(tmp_path), "capture-0001"]) == 1
    verification = _payload(capsys)
    assert verification["status"] == "TAMPERED"
    checks = verification["checks"]  # type: ignore[assignment]
    assert any(not check["matches"] for check in checks)  # type: ignore[union-attr]


def test_cli_recover_and_gc_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    partial = tmp_path / "partial" / "abandoned.partial"
    partial.mkdir(parents=True)
    _capture(tmp_path)
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))

    assert main(["recover", "--spool-root", str(tmp_path)]) == 0
    recovered = _payload(capsys)
    assert recovered["status"] == "RECOVERED"
    assert (partial / "recovery.json").exists()

    before_gc = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    assert main(["gc", "--spool-root", str(tmp_path), "--dry-run"]) == 0
    gc = _payload(capsys)
    assert gc == {
        "candidates": ["capture-0001"],
        "deleted": [],
        "dry_run": True,
        "status": "DRY_RUN",
    }
    assert sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*")) == before_gc
    assert before != before_gc  # recovery is intentionally the only mutation in this test.


def test_cli_run_uses_literal_argv_and_safe_envelope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "run",
                "--spool-root",
                str(tmp_path / "spool"),
                "--",
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1])",
                "$(not-a-shell)",
            ]
        )
        == 0
    )
    payload = _payload(capsys)
    assert payload["mode"] == "enforce"
    envelope = payload["envelope"]  # type: ignore[assignment]
    assert "$(not-a-shell)" in envelope["projection"]["inline_text"]  # type: ignore[index]
    assert str(tmp_path) not in json.dumps(payload)


def test_cli_run_honors_explicit_projection_limits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "run",
                "--spool-root",
                str(tmp_path / "spool"),
                "--max-projection-bytes",
                "48",
                "--max-projection-lines",
                "2",
                "--max-projection-tokens",
                "12",
                "--",
                sys.executable,
                "-c",
                "print('alpha\\nbeta\\ngamma\\ndelta')",
            ]
        )
        == 0
    )
    envelope = _payload(capsys)["envelope"]  # type: ignore[assignment]
    projection = envelope["projection"]  # type: ignore[index]
    assert projection["bytes"] <= 48  # type: ignore[index]
    assert projection["lines"] <= 2  # type: ignore[index]
    assert projection["estimated_tokens"] <= 12  # type: ignore[index]


def test_cli_run_preserves_wrapped_command_exit_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "run",
                "--spool-root",
                str(tmp_path / "spool"),
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(7)",
            ]
        )
        == 7
    )
    payload = _payload(capsys)
    assert payload["command"] == {
        "cancelled": False,
        "exit_code": 7,
        "signal": None,
        "timed_out": False,
    }


def test_cli_explicit_mode_overrides_ambient_mode_except_break_glass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OUTCTL_MODE", "shadow")
    assert (
        main(
            [
                "run",
                "--mode",
                "enforce",
                "--spool-root",
                str(tmp_path / "spool"),
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        == 0
    )
    assert _payload(capsys)["mode"] == "enforce"

    monkeypatch.setenv("OUTCTL_ENABLED", "0")
    assert (
        main(
            [
                "run",
                "--mode",
                "enforce",
                "--spool-root",
                str(tmp_path / "unused"),
                "--",
                sys.executable,
                "-c",
                "pass",
            ]
        )
        == 0
    )
    assert _payload(capsys)["mode"] == "bypass"


def test_cli_validates_raw_free_pilot_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = {
        "pilot": {
            "harness": "claude",
            "command_class": "appservice-health-check",
            "policy_digest": "sha256:" + "a" * 64,
        },
        "baseline": {"exposed_tokens": 300},
        "enforce": {
            "raw_tokens": 700,
            "exposed_tokens": 200,
            "retrieved_tokens": 20,
            "retrieval_count": 1,
            "wall_time_ms": 900,
            "wrapper_overhead_ms": 80,
        },
        "assessment": {
            "harness_native_context_management": "visible truncation",
            "outctl_increment": "bounded range retrieval",
            "recommendation": "continue",
        },
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    assert main(["pilot-validate", str(path)]) == 0
    assert _payload(capsys)["status"] == "VALID"


def test_cli_exposes_rollback_and_enablement_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["rollback-check"]) == 0
    assert _payload(capsys)["passed"] is True

    evidence = tmp_path / "enablement.json"
    evidence.write_text(
        json.dumps(
            {
                "foundation": {
                    "schemas_valid": True,
                    "policy_digest_stable": True,
                    "full_repository_gate": True,
                },
                "mechanism": {
                    "passed": True,
                    "process_semantics_passed": True,
                    "security_passed": True,
                },
            }
        ),
        encoding="utf-8",
    )
    assert main(["enablement", str(evidence)]) == 0
    payload = _payload(capsys)
    assert payload["highest_contiguous_stage"] == 1
    next_stage = payload["next_stage"]
    assert isinstance(next_stage, dict)
    assert next_stage["name"] == "runner-owned-identity-boundary"
