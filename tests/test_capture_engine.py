from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from outctl.capture import capture_command, recover_partials
from outctl.capture.storage import StreamWriter


def run(argv: list[str], root: Path, **kwargs: object):
    return asyncio.run(capture_command(argv, root, **kwargs))


def test_captures_stdout_with_private_spool(tmp_path: Path) -> None:
    result = run([sys.executable, "-c", "print('hello')"], tmp_path, max_bytes=1024)
    assert result.command.exit_code == 0
    assert result.capture_status == "COMPLETE"
    assert result.stdout_bytes == 6
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o700
    assert stat.S_IMODE((result.path / "stdout.raw").stat().st_mode) == 0o600


def test_nonzero_command_does_not_fail_capture(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "import sys; sys.stderr.write('bad'); raise SystemExit(7)"],
        tmp_path,
        max_bytes=1024,
    )
    assert result.command.exit_code == 7
    assert result.capture_status == "COMPLETE"
    assert result.stderr_bytes == 3


def test_concurrently_drains_large_mixed_streams(tmp_path: Path) -> None:
    code = (
        "import sys; "
        "[(sys.stdout.write('o'*65536), sys.stderr.write('e'*65536)) for _ in range(4)]"
    )
    result = run([sys.executable, "-c", code], tmp_path, max_bytes=1024 * 1024, timeout=5)
    assert result.command.exit_code == 0
    assert result.stdout_bytes == 4 * 65536
    assert result.stderr_bytes == 4 * 65536
    events = [json.loads(line) for line in (result.path / "events.ndjson").read_text().splitlines()]
    assert [event["seq"] for event in events] == list(range(len(events)))


def test_argv_is_literal_and_shell_input_is_rejected(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(not-a-shell)"],
        tmp_path,
        max_bytes=1024,
    )
    assert result.command.exit_code == 0
    assert result.stdout_bytes == len("$(not-a-shell)\n")
    with pytest.raises(TypeError):
        run("echo hello", tmp_path, max_bytes=1)  # type: ignore[arg-type]


def test_quota_keeps_prefix_but_drains_process(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000)"],
        tmp_path,
        max_bytes=10,
        timeout=5,
    )
    assert result.command.exit_code == 0
    assert result.capture_status == "TRUNCATED"
    assert result.stdout_bytes == 10
    assert os.path.getsize(result.path / "stdout.raw") == 10


def test_timeout_kills_the_process_group_and_preserves_result_status(tmp_path: Path) -> None:
    result = run(
        [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(60)"],
        tmp_path,
        max_bytes=1024,
        timeout=0.1,
    )
    assert result.command.timed_out is True
    assert result.command.signals_sent == (9,)
    assert result.capture_status == "COMPLETE"


def test_storage_failure_fails_open_without_stopping_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_write = StreamWriter.write

    def fail_stdout(self: StreamWriter, chunk: bytes) -> None:
        if self.path.name == "stdout.raw":
            raise OSError("injected full disk")
        original_write(self, chunk)

    monkeypatch.setattr(StreamWriter, "write", fail_stdout)
    result = run([sys.executable, "-c", "print('still-runs')"], tmp_path, max_bytes=1024)
    assert result.command.exit_code == 0
    assert result.capture_status == "CAPTURE_FAILED"


def test_required_capture_failure_stops_child_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_write(self: StreamWriter, chunk: bytes) -> None:
        raise OSError("injected full disk")

    monkeypatch.setattr(StreamWriter, "write", fail_write)
    result = run(
        [sys.executable, "-c", "import sys, time; print('started', flush=True); time.sleep(60)"],
        tmp_path,
        max_bytes=1024,
        required_capture=True,
        timeout=5,
    )
    assert result.command.signal == 9
    assert result.command.timed_out is False
    assert result.capture_status == "CAPTURE_FAILED"


def test_recovery_marks_partial_without_execution(tmp_path: Path) -> None:
    partial = tmp_path / "partial" / "abandoned.partial"
    partial.mkdir(parents=True)
    records = recover_partials(tmp_path)
    assert records == [records[0]]
    assert records[0].capture_id == "abandoned"
    assert json.loads((partial / "recovery.json").read_text())["capture_status"] == "INCOMPLETE"
