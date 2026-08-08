from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from outctl.adapter import (
    AdapterIdentity,
    AdapterMode,
    AdapterRequest,
    run_adapter,
)


def run(request: AdapterRequest):
    return asyncio.run(run_adapter(request))


def request(mode: AdapterMode, tmp_path: Path, code: str, **kwargs: object) -> AdapterRequest:
    return AdapterRequest(
        mode=mode,
        argv=(sys.executable, "-c", code),
        policy_ref="pilot",
        policy_digest="sha256:" + "1" * 64,
        identity=AdapterIdentity(host_id="test-host", harness="pytest"),
        spool_root=tmp_path / "spool",
        **kwargs,
    )


def test_bypass_executes_directly_without_creating_capture_root(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    result = run(
        request(
            AdapterMode.BYPASS,
            tmp_path,
            "from pathlib import Path; Path('ran').write_text('yes')",
            cwd=tmp_path,
        )
    )

    assert result.command.exit_code == 0
    assert marker.read_text() == "yes"
    assert result.capture is result.envelope is result.receipt is None
    assert not (tmp_path / "spool").exists()


def test_shadow_returns_command_outcome_and_observation(tmp_path: Path) -> None:
    result = run(request(AdapterMode.SHADOW, tmp_path, "print('observed'); raise SystemExit(7)"))

    assert result.command.exit_code == 7
    assert result.capture is not None
    assert result.capture.capture_status == "COMPLETE"
    assert result.envelope is not None
    assert result.envelope.command.exit_code == 7
    assert result.envelope.projection.inline_text == "observed\n"
    assert result.receipt is not None
    assert result.receipt["mode"] == "shadow"


def test_enforce_keeps_command_and_capture_status_distinct(tmp_path: Path) -> None:
    result = run(
        request(AdapterMode.ENFORCE, tmp_path, "print('too much')", max_capture_bytes=1)
    )

    assert result.command.exit_code == 0
    assert result.capture is not None
    assert result.capture.capture_status == "TRUNCATED"
    assert result.envelope is not None
    assert result.envelope.capture.status == "CAPTURE_TRUNCATED"
    assert result.receipt is not None
    assert result.receipt["capture"] == {
        "status": "CAPTURE_TRUNCATED",
        "stdout_bytes": 1,
        "stderr_bytes": 0,
    }


def test_receipt_is_json_safe_and_excludes_output_and_raw_paths(tmp_path: Path) -> None:
    secret = "unique-raw-output-secret"
    result = run(request(AdapterMode.ENFORCE, tmp_path, f"print({secret!r})"))

    assert result.receipt is not None
    serialized = json.dumps(result.receipt, sort_keys=True)
    assert secret not in serialized
    assert str(tmp_path.resolve()) not in serialized
    assert "inline_text" not in serialized
    assert "stdout.raw" not in serialized


def test_timeout_and_cwd_are_forwarded(tmp_path: Path) -> None:
    cwd = tmp_path / "work"
    cwd.mkdir()
    cwd_result = run(
        request(
            AdapterMode.SHADOW,
            tmp_path,
            "import os; print(os.getcwd())",
            cwd=cwd,
        )
    )
    timeout_result = run(
        request(AdapterMode.ENFORCE, tmp_path, "import time; time.sleep(60)", timeout=0.05)
    )

    assert cwd_result.envelope is not None
    assert cwd_result.envelope.projection.inline_text == f"{cwd}\n"
    assert timeout_result.command.timed_out is True
    assert timeout_result.command.signal == 9


def test_action_and_audit_bindings_are_passed_through_only(tmp_path: Path) -> None:
    bindings = {"action_id": "action-7", "audit_id": "audit-9"}
    result = run(request(AdapterMode.SHADOW, tmp_path, "pass", bindings=bindings))

    assert result.envelope is not None
    assert result.envelope.bindings == bindings
    assert result.receipt is not None
    assert result.receipt["bindings"] == bindings
    assert list(tmp_path.rglob("*action*")) == []
    assert list(tmp_path.rglob("*audit*")) == []
