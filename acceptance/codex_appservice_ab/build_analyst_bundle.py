#!/usr/bin/env python3
"""Build a deterministic raw-free analyst or reproducibility bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

EXCLUDED_PARTS = {".git", ".venv", "__pycache__", "private", ".outctl"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
REPRODUCIBILITY_ROOTS = (
    "src",
    "tests",
    "schemas",
    "config",
    "acceptance/SCENARIOS.md",
    "acceptance/codex_appservice_ab",
    "pyproject.toml",
    "uv.lock",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _commit(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _safe_files(root: Path, selected: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for candidate in selected:
        path = (root / candidate).resolve()
        if not path.is_relative_to(root) or not path.exists():
            raise ValueError(f"bundle input is missing or outside repository: {candidate}")
        entries = [path] if path.is_file() else list(path.rglob("*"))
        for entry in entries:
            relative = entry.relative_to(root)
            if (
                entry.is_file()
                and not entry.is_symlink()
                and not (set(relative.parts) & EXCLUDED_PARTS)
                and entry.suffix not in EXCLUDED_SUFFIXES
            ):
                files.add(relative)
    return sorted(files, key=lambda item: item.as_posix())


def build(root: Path, output: Path, package_class: str, inputs: list[Path]) -> None:
    selected = inputs or (
        [Path(item) for item in REPRODUCIBILITY_ROOTS]
        if package_class == "reproducibility"
        else [Path("acceptance/codex_appservice_ab"), Path("docs/PILOT_ASSESSMENT.md")]
    )
    files = _safe_files(root, selected)
    inventory = []
    bodies: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    for relative in files:
        body = (root / relative).read_bytes()
        name = relative.as_posix()
        bodies[name] = body
        mode = (root / relative).stat().st_mode & 0o777
        modes[name] = mode
        inventory.append(
            {
                "path": name,
                "mode": f"{mode:04o}",
                "bytes": len(body),
                "sha256": _sha256(body),
            }
        )
    manifest = {
        "schema_version": 1,
        "package_class": package_class,
        "raw_capture_bytes_included": False,
        "repository_commit": _commit(root),
        "harness_commit": _commit(root),
        "inventory_excludes_self": "bundle-manifest.json",
        "files": inventory,
    }
    bodies["bundle-manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(bodies):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            mode = modes.get(name, 0o600)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, bodies[name])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--package-class", choices=("analyst-safe", "reproducibility"), required=True
    )
    parser.add_argument("inputs", nargs="*", type=Path)
    args = parser.parse_args()
    build(args.root.resolve(), args.output.resolve(), args.package_class, args.inputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
