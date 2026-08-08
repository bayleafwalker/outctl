from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import outctl.capture.runner
from outctl.retrieval import (
    RetrievalStatus,
    inspect_capture,
    search_stream,
    slice_stream,
    tail_stream,
    verify_capture,
)


def _capture(
    root: Path, capture_id: str = "capture-1", *, workspace_id: str | None = None
) -> Path:
    path = root / "captures" / capture_id
    path.mkdir(parents=True)
    stdout = b"alpha\nbeta marker\ngamma\n"
    stderr = b"warning\n"
    events = b'{"seq":0,"stream":"stdout"}\n'
    for name, data in (("stdout.raw", stdout), ("stderr.raw", stderr), ("events.ndjson", events)):
        (path / name).write_bytes(data)
        os.chmod(path / name, 0o600)
    manifest = {
        "capture_id": capture_id,
        "capture_status": "COMPLETE",
        "streams": {
            "stdout": {"bytes": len(stdout), "sha256": hashlib.sha256(stdout).hexdigest()},
            "stderr": {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()},
        },
        "event_index": {"events": 1, "sha256": hashlib.sha256(events).hexdigest()},
    }
    if workspace_id is not None:
        manifest["source"] = {"workspace_id": workspace_id}
    (path / "manifest.json").write_text(json.dumps(manifest))
    os.chmod(path / "manifest.json", 0o600)
    return path


def test_inspect_slice_tail_and_search_are_local_read_only(tmp_path: Path) -> None:
    _capture(tmp_path)

    inspected = inspect_capture(tmp_path, "capture-1")
    assert inspected.status is RetrievalStatus.AVAILABLE
    assert inspected.capture_status == "COMPLETE"

    sliced = slice_stream(tmp_path, "capture-1", "stdout", 6, 17)
    assert sliced.status is RetrievalStatus.AVAILABLE
    assert sliced.data == b"beta marker"

    tailed = tail_stream(tmp_path, "capture-1", "stdout", lines=1)
    assert tailed.data == b"gamma\n"

    exact = search_stream(tmp_path, "capture-1", "stdout", b"marker", context_bytes=4)
    regex = search_stream(tmp_path, "capture-1", "stdout", rb"beta\s+marker", regex=True)
    assert [(match.start, match.end) for match in exact.matches] == [(11, 17)]
    assert len(regex.matches) == 1
    assert exact.matches[0].context == b"eta marker\ngam"


def test_tail_is_bounded_and_marks_a_byte_limited_suffix(tmp_path: Path) -> None:
    path = _capture(tmp_path)
    (path / "stdout.raw").write_bytes(b"first\nsecond\nthird\n")
    result = tail_stream(tmp_path, "capture-1", "stdout", lines=2, max_bytes=13)
    assert result.status is RetrievalStatus.AVAILABLE
    assert result.truncated is True
    assert result.data == b"second\nthird\n"


def test_verify_reports_expected_and_observed_digest_after_tampering(tmp_path: Path) -> None:
    path = _capture(tmp_path)
    before = verify_capture(tmp_path, "capture-1")
    assert before.status is RetrievalStatus.AVAILABLE

    (path / "stdout.raw").write_bytes(b"modified\n")
    result = verify_capture(tmp_path, "capture-1")
    stdout = next(check for check in result.checks if check.artifact == "stdout")
    assert result.status is RetrievalStatus.TAMPERED
    assert stdout.expected is not None
    assert stdout.observed == hashlib.sha256(b"modified\n").hexdigest()
    assert stdout.expected != stdout.observed


def test_partial_and_missing_captures_do_not_invent_a_final_state(tmp_path: Path) -> None:
    partial = tmp_path / "partial" / "interrupted.partial"
    partial.mkdir(parents=True)

    assert inspect_capture(tmp_path, "interrupted").status is RetrievalStatus.INCOMPLETE
    assert (
        slice_stream(tmp_path, "interrupted", "stdout", 0, 1).status is RetrievalStatus.INCOMPLETE
    )
    assert verify_capture(tmp_path, "missing").status is RetrievalStatus.UNAVAILABLE


def test_retrieval_never_invokes_the_command_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(tmp_path)
    invoked = False

    async def fail_if_called(*args: object, **kwargs: object) -> object:
        nonlocal invoked
        invoked = True
        raise AssertionError("retrieval must not run commands")

    monkeypatch.setattr(outctl.capture.runner, "capture_command", fail_if_called)
    assert slice_stream(tmp_path, "capture-1", "stdout", 0, 5).status is RetrievalStatus.AVAILABLE
    assert invoked is False


def test_workspace_authorization_denies_known_capture_in_another_workspace(tmp_path: Path) -> None:
    _capture(tmp_path, workspace_id="workspace-owned")

    assert (
        inspect_capture(
            tmp_path, "capture-1", expected_workspace_id="workspace-other"
        ).status
        is RetrievalStatus.DENIED
    )
    assert (
        slice_stream(
            tmp_path, "capture-1", "stdout", 0, 5, expected_workspace_id="workspace-other"
        ).status
        is RetrievalStatus.DENIED
    )
    assert (
        tail_stream(
            tmp_path, "capture-1", "stdout", expected_workspace_id="workspace-other"
        ).status
        is RetrievalStatus.DENIED
    )
    assert (
        search_stream(
            tmp_path, "capture-1", "stdout", b"marker", expected_workspace_id="workspace-other"
        ).status
        is RetrievalStatus.DENIED
    )
    assert (
        verify_capture(
            tmp_path, "capture-1", expected_workspace_id="workspace-other"
        ).status
        is RetrievalStatus.DENIED
    )
    assert (
        inspect_capture(
            tmp_path, "capture-1", expected_workspace_id="workspace-owned"
        ).status
        is RetrievalStatus.AVAILABLE
    )


@pytest.mark.parametrize("capture_id", ("../outside", "nested/name", ".."))
def test_traversal_and_symlinked_capture_paths_are_denied(tmp_path: Path, capture_id: str) -> None:
    _capture(tmp_path)
    assert inspect_capture(tmp_path, capture_id).status is RetrievalStatus.DENIED

    target = tmp_path / "captures" / "capture-1"
    (tmp_path / "captures" / "linked").symlink_to(target, target_is_directory=True)
    assert inspect_capture(tmp_path, "linked").status is RetrievalStatus.DENIED
