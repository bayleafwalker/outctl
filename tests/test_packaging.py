from __future__ import annotations

import importlib.metadata
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_project_keeps_legacy_console_script_and_separate_w2_namespaces() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["scripts"] == {"outctl": "outctl.cli:main"}
    assert project["project"]["name"] == "outctl"
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/outctl"]
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    assert workspace["workspace"]["resolver"] == "2"
    assert "crates/outctl-cli" in workspace["workspace"]["members"]


def test_installed_metadata_has_one_legacy_command() -> None:
    distributions = [
        dist for dist in importlib.metadata.distributions() if dist.metadata["Name"] == "outctl"
    ]
    assert distributions, "the uv environment should expose the editable outctl distribution"
    commands = [
        entry.value
        for dist in distributions
        for entry in dist.entry_points
        if entry.group == "console_scripts" and entry.name == "outctl"
    ]
    assert commands == ["outctl.cli:main"]


def test_native_artifact_has_a_distinct_binary_name_and_no_python_script_collision() -> None:
    native_package = tomllib.loads(
        (ROOT / "crates/outctl-cli/Cargo.toml").read_text(encoding="utf-8")
    )
    assert native_package["bin"] == [{"name": "outctl-native", "path": "src/main.rs"}]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "outctl-native" not in project["project"]["scripts"]


def test_control_namespace_does_not_eagerly_import_legacy_engine() -> None:
    probe = (
        "import sys; import outctl.control; import outctl.native; "
        "assert 'outctl.cli' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", probe], cwd=ROOT, check=True)


def test_built_wheel_contains_python_and_native_skeleton_members() -> None:
    wheels = sorted((ROOT / "dist").glob("outctl-*.whl"))
    assert len(wheels) == 1, "package gate must produce exactly one wheel in dist/"
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    assert {
        "outctl/__init__.py",
        "outctl/cli.py",
        "outctl/control/__init__.py",
        "outctl/extensions/__init__.py",
        "outctl/extensions/commissioning.py",
        "outctl/extensions/contracts.py",
        "outctl/extensions/discovery.py",
        "outctl/extensions/protocol.py",
        "outctl/extensions/slow_path.py",
        "outctl/extensions/worker.py",
        "outctl/native/__init__.py",
        "outctl/native/differential.py",
        "outctl/native/rollout.py",
        "outctl/native/selector.py",
    }.issubset(names)
    assert not {"outctl.py", "outctl_native.py"}.intersection(names)
