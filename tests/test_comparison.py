from __future__ import annotations

import hashlib

from outctl import compare_direct_wrapped, make_direct_reference


def _make_wrapped(
    argv: list[str],
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    cwd: str = "/tmp",
) -> dict:
    return {
        "invocation": {
            "argv_display": argv,
            "shell": False,
            "cwd": cwd,
            "host_id": "testhost",
            "harness": "outctl",
            "started_at": "2026-08-03T18:00:00Z",
        },
        "command": {
            "started": True,
            "exit_code": exit_code,
            "signal": None,
            "timed_out": False,
            "cancelled": False,
        },
        "capture": {
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        },
    }


def test_identical_results_match() -> None:
    direct = make_direct_reference(["echo", "hi"], stdout=b"hi\n")
    wrapped = _make_wrapped(["echo", "hi"], stdout=b"hi\n")
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is True
    assert result.exit_match is True
    assert result.stdout_match is True
    assert result.stderr_match is True
    assert result.cwd_match is True


def test_exit_code_difference_detected() -> None:
    direct = make_direct_reference(["false"], exit_code=1)
    wrapped = _make_wrapped(["false"], exit_code=0)
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is False
    assert result.exit_match is False
    assert "exit code differs" in result.differences[0]


def test_stdout_difference_detected() -> None:
    direct = make_direct_reference(["echo", "a"], stdout=b"a\n")
    wrapped = _make_wrapped(["echo", "a"], stdout=b"b\n")
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is False
    assert result.stdout_match is False
    assert any("stdout" in diff for diff in result.differences)


def test_cwd_difference_detected() -> None:
    direct = make_direct_reference(["pwd"], cwd="/tmp")
    wrapped = _make_wrapped(["pwd"], cwd="/var")
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is False
    assert result.cwd_match is False


def test_signal_difference_detected() -> None:
    direct = make_direct_reference(["sleep", "10"])
    direct["command"]["signal"] = 15
    wrapped = _make_wrapped(["sleep", "10"])
    wrapped["command"]["signal"] = 9
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is False
    assert result.signal_match is False


def test_wrapper_env_variable_allowed() -> None:
    direct = make_direct_reference(["env"])
    direct["invocation"]["env"] = {"PATH": "/bin"}
    wrapped = _make_wrapped(["env"])
    wrapped["invocation"]["env"] = {"PATH": "/bin", "OUTCTL_VERSION": "1"}
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is True


def test_unexpected_env_variable_flagged() -> None:
    direct = make_direct_reference(["env"])
    direct["invocation"]["env"] = {"PATH": "/bin"}
    wrapped = _make_wrapped(["env"])
    wrapped["invocation"]["env"] = {"PATH": "/bin", "EVIL_INJECTION": "1"}
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is False
    assert any("EVIL_INJECTION" in diff for diff in result.differences)


def test_env_value_change_flagged() -> None:
    direct = make_direct_reference(["env"])
    direct["invocation"]["env"] = {"PATH": "/bin"}
    wrapped = _make_wrapped(["env"])
    wrapped["invocation"]["env"] = {"PATH": "/usr/bin"}
    result = compare_direct_wrapped(direct, wrapped)
    assert result.matches is False
    assert any("PATH" in diff for diff in result.differences)


def test_bytes_fallback_when_hashes_absent() -> None:
    direct = make_direct_reference(["echo", "hi"], stdout=b"hi\n")
    del direct["capture"]["stdout_sha256"]
    wrapped = _make_wrapped(["echo", "hi"], stdout=b"hi\n")
    del wrapped["capture"]["stdout_sha256"]
    result = compare_direct_wrapped(direct, wrapped)
    assert result.stdout_match is True
