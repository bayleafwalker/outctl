"""Validate the install-facing shape of a built outctl wheel."""

from __future__ import annotations

import argparse
import configparser
import zipfile
from pathlib import Path


def _wheel_path(value: str | None) -> Path:
    if value:
        path = Path(value)
        if not path.is_file():
            raise SystemExit(f"wheel does not exist: {path}")
        return path
    wheels = sorted(Path("dist").glob("outctl-*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one outctl wheel in dist/, found {len(wheels)}")
    return wheels[0]


def check(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        metadata_name = next(
            name
            for name in names
            if name.startswith("outctl-") and name.endswith(".dist-info/METADATA")
        )
        entry_points_name = metadata_name.removesuffix("METADATA") + "entry_points.txt"
        metadata = archive.read(metadata_name).decode("utf-8")
        entry_points = configparser.ConfigParser()
        entry_points.read_string(archive.read(entry_points_name).decode("utf-8"))

        required = {
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
            "outctl/native/selector.py",
        }
        missing = required - names
        if missing:
            raise SystemExit(f"wheel is missing required members: {sorted(missing)}")

        collisions = {"outctl.py", "outctl_native.py"}
        collisions.intersection_update(names)
        if collisions:
            raise SystemExit(f"wheel contains module/package collisions: {sorted(collisions)}")

        if "Name: outctl\n" not in metadata:
            raise SystemExit("wheel metadata does not identify the outctl distribution")

        scripts = dict(entry_points.items("console_scripts", raw=True))
        if scripts != {"outctl": "outctl.cli:main"}:
            raise SystemExit(f"unexpected console metadata: {scripts!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", nargs="?")
    args = parser.parse_args()
    check(_wheel_path(args.wheel))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
