from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from outctl.cli import main
from outctl.observations import (
    ObservationError,
    compare_observations,
    import_observation,
    ingest_observation,
    observation_summary,
)


def _metadata() -> dict[str, object]:
    return {
        "source": {"harness": "codex", "session": "session-1", "tool_call": "call-1"},
        "invocation": {
            "tool": "exec_command",
            "command_sha256": "a" * 64,
        },
        "result": {"exit_code": 0, "duration_ms": 417},
    }


def _import(root: Path, *, stdout: bytes = b"alpha\nbeta marker\n") -> dict[str, object]:
    stdout_path = root / "stdout.txt"
    stderr_path = root / "stderr.txt"
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(b"warning\n")
    return import_observation(
        root / "spool",
        stdout_path,
        stderr_path,
        _metadata(),
        exit_code=0,
    )


def test_import_creates_stable_raw_free_observation_and_retrieves_it(tmp_path: Path) -> None:
    record = _import(tmp_path)
    observation_id = str(record["observation_id"])
    assert observation_id.startswith("obs-")
    assert record["result"] == {
        "duration_ms": 417,
        "exit_code": 0,
        "stderr": "artifact:sha256:" + hashlib.sha256(b"warning\n").hexdigest(),
        "stdout": "artifact:sha256:" + hashlib.sha256(b"alpha\nbeta marker\n").hexdigest(),
    }
    summary = observation_summary(tmp_path / "spool", observation_id)
    assert summary["capture"]["verified"] is True  # type: ignore[index]
    assert summary["retention"] == {"state": "temporary"}  # type: ignore[comparison-overlap]

    same = ingest_observation(tmp_path / "spool", str(record["capture_id"]), _metadata())
    assert same["observation_id"] == observation_id
    assert str(tmp_path) not in json.dumps(summary)


def test_cli_observation_commands_are_bounded_and_do_not_rerun(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _import(tmp_path)
    spool = str(tmp_path / "spool")
    observation_id = str(record["observation_id"])

    assert main(["show", "--spool-root", spool, observation_id]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["observation_id"] == observation_id
    assert "alpha" not in json.dumps(shown)

    assert main(["stdout", "--spool-root", spool, observation_id, "--max-bytes", "64"]) == 0
    stdout = json.loads(capsys.readouterr().out)
    assert stdout["projection"]["text"] == "alpha\nbeta marker\n"

    assert main(["grep", "--spool-root", spool, observation_id, "marker"]) == 0
    grep = json.loads(capsys.readouterr().out)
    assert len(grep["matches"]) == 1

    assert main(["pin", "--spool-root", spool, observation_id, "--reason", "diagnosis"]) == 0
    capsys.readouterr()
    assert main(["show", "--spool-root", spool, observation_id]) == 0
    pinned = json.loads(capsys.readouterr().out)
    assert pinned["retention"]["action"] == "pin"


def test_diff_compares_artifact_identity_without_exposing_bodies(tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    left_stdout = tmp_path / "left.stdout"
    right_stdout = tmp_path / "right.stdout"
    left_stderr = tmp_path / "left.stderr"
    right_stderr = tmp_path / "right.stderr"
    left_stdout.write_bytes(b"same\n")
    right_stdout.write_bytes(b"different\n")
    left_stderr.write_bytes(b"")
    right_stderr.write_bytes(b"")
    left = import_observation(spool, left_stdout, left_stderr, _metadata(), exit_code=0)
    right = import_observation(spool, right_stdout, right_stderr, _metadata(), exit_code=0)
    result = compare_observations(spool, str(left["observation_id"]), str(right["observation_id"]))
    assert result["same_result"] is False
    assert result["streams"]["stdout"]["same"] is False  # type: ignore[index]


def test_import_rejects_symlinked_external_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"secret-like output")
    linked = tmp_path / "linked"
    linked.symlink_to(source)
    with pytest.raises(ObservationError):
        import_observation(tmp_path / "spool", linked, None, _metadata(), exit_code=0)
