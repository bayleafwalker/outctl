from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required")


def _native_binary() -> Path:
    subprocess.run(
        ["cargo", "build", "--quiet", "--package", "outctl-cli", "--bin", "outctl-native"],
        cwd=ROOT,
        check=True,
    )
    return ROOT / "target/debug/outctl-native"


def test_generic_ordinary_command_starts_no_python_slow_path(tmp_path: Path) -> None:
    marker = tmp_path / "python-started"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("python", "python3", "uv"):
        executable = fake_bin / name
        executable.write_text(
            f"#!/bin/sh\nprintf started > {marker}\nexit 99\n",
            encoding="utf-8",
        )
        executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    spool = tmp_path / "spool"
    completed = subprocess.run(
        [
            str(_native_binary()),
            "run",
            "--spool-root",
            str(spool),
            "--",
            "/run/current-system/sw/bin/printf",
            "generic-unknown-ok",
        ],
        env={"PATH": str(fake_bin)},
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert Path(result["path"]).joinpath("stdout.raw").read_bytes() == b"generic-unknown-ok"
    assert not marker.exists()


def test_cli_stdin_is_null_by_default_and_inherited_only_when_selected(tmp_path: Path) -> None:
    binary = _native_binary()
    command = ["/run/current-system/sw/bin/wc", "-c"]
    null_result = subprocess.run(
        [str(binary), "run", "--spool-root", str(tmp_path / "null"), "--", *command],
        input=b"not inherited",
        check=True,
        capture_output=True,
    )
    null_value = json.loads(null_result.stdout)
    assert Path(null_value["path"]).joinpath("stdout.raw").read_text().strip() == "0"

    inherited_result = subprocess.run(
        [
            str(binary),
            "run",
            "--spool-root",
            str(tmp_path / "inherited"),
            "--stdin",
            "inherit",
            "--",
            *command,
        ],
        input=b"five!",
        check=True,
        capture_output=True,
        env={**os.environ},
    )
    inherited_value = json.loads(inherited_result.stdout)
    assert Path(inherited_value["path"]).joinpath("stdout.raw").read_text().strip() == "5"
