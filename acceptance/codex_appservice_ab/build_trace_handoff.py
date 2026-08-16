#!/usr/bin/env python3
"""Build a portable checked runtime-trace handoff archive.

The input run directory remains private.  The archive uses relative paths and
includes a relative SHA256SUMS manifest.  Shell homes and generated tooling
directories are excluded because they can contain credentials or local
execution state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

EXCLUDED_PRIVATE_PARTS = {"codex-home", "shell-home", "tooling", "tmp", "uv-cache"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_relative(value: str, source_root: Path) -> str | None:
    try:
        return Path(value).resolve().relative_to(source_root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _augment_report(value: Any, source_root: Path) -> Any:
    if isinstance(value, Mapping):
        result = {str(key): _augment_report(item, source_root) for key, item in value.items()}
        private_artifacts = value.get("private_artifacts")
        if isinstance(private_artifacts, Mapping):
            relative_paths = {
                str(key): relative
                for key, item in private_artifacts.items()
                if isinstance(item, str)
                and (relative := _archive_relative(item, source_root)) is not None
            }
            result["private_artifacts"] = {
                **result.get("private_artifacts", {}),
                "archive_relative_paths": relative_paths,
            }
        return result
    if isinstance(value, list):
        return [_augment_report(item, source_root) for item in value]
    return value


def _copy_selected(
    source_root: Path,
    staging: Path,
    observer: Path | None,
    observers: Sequence[Path] = (),
) -> list[Path]:
    selected: list[tuple[Path, Path]] = []
    for relative in (Path("HANDOFF.md"), Path("report.json"), Path("planned-commands.json")):
        source = source_root / relative
        if source.is_file():
            selected.append((source, relative))

    private_root = source_root / "private"
    if private_root.is_dir():
        for source in sorted(private_root.rglob("*")):
            relative_source = source.relative_to(private_root)
            excluded = any(
                part in EXCLUDED_PRIVATE_PARTS
                or any(part.startswith(prefix + "-") for prefix in EXCLUDED_PRIVATE_PARTS)
                for part in relative_source.parts
            )
            if not source.is_file() or excluded:
                continue
            selected.append((source, Path("private") / relative_source))

    observer_paths = ([observer] if observer is not None else []) + list(observers)
    selected_names: set[str] = set()
    for observer_path in observer_paths:
        observer_path = observer_path.resolve()
        if not observer_path.is_file():
            raise ValueError(f"observer source is missing: {observer_path}")
        if observer_path.name in selected_names:
            continue
        selected_names.add(observer_path.name)
        selected.append((observer_path, Path("source") / observer_path.name))

    if not selected:
        raise ValueError(f"no handoff files found under {source_root}")

    for source, relative in selected:
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if relative == Path("report.json"):
            report = json.loads(source.read_text(encoding="utf-8"))
            report = _augment_report(report, source_root)
            report.setdefault("handoff_packaging", {})
            report["handoff_packaging"].update(
                {
                    "archive_paths_relative": True,
                    "excluded_private_subtrees": sorted(EXCLUDED_PRIVATE_PARTS),
                }
            )
            destination.write_text(
                json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
        else:
            shutil.copyfile(source, destination)
        mode = 0o600 if "private" in relative.parts or relative.name == "report.json" else 0o644
        os.chmod(destination, mode)

    return sorted(
        path.relative_to(staging)
        for path in staging.rglob("*")
        if path.is_file()
    )


def _write_checksums(staging: Path, files: list[Path]) -> None:
    lines = [f"{_sha256(staging / relative)}  {relative.as_posix()}" for relative in files]
    (staging / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(staging / "SHA256SUMS", 0o644)


def _write_tarball(staging: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as archive:
        for path in sorted(staging.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(staging).as_posix()
            info = archive.gettarinfo(str(path), arcname=relative)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            with path.open("rb") as handle:
                archive.addfile(info, handle)


def build(
    source_root: Path,
    output: Path,
    observer: Path | None = None,
    observers: Sequence[Path] = (),
) -> Path:
    source_root = source_root.resolve()
    output = output.resolve()
    if not source_root.is_dir():
        raise ValueError(f"source run directory is missing: {source_root}")
    with tempfile.TemporaryDirectory(prefix="outctl-trace-handoff-") as temporary:
        staging = Path(temporary) / "handoff"
        staging.mkdir()
        files = _copy_selected(source_root, staging, observer, observers)
        _write_checksums(staging, files)
        _write_tarball(staging, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--observer", type=Path, action="append")
    args = parser.parse_args()
    observer_paths = args.observer or []
    print(
        build(
            args.source_root,
            args.output,
            observers=observer_paths,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
