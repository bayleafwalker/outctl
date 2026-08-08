"""Private spool-directory primitives used by the capture runner."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass
class StreamWriter:
    """Incrementally write one stream without retaining its contents."""

    path: Path
    _file: BinaryIO
    _hash: hashlib._Hash
    retained_bytes: int = 0

    @classmethod
    def create(cls, path: Path) -> StreamWriter:
        file = path.open("xb")
        os.chmod(path, 0o600)
        return cls(path=path, _file=file, _hash=hashlib.sha256())

    def write(self, chunk: bytes) -> None:
        # BinaryIO is deliberately kept private: callers only stream chunks.
        self._file.write(chunk)
        self._hash.update(chunk)
        self.retained_bytes += len(chunk)

    def close(self) -> None:
        self._file.close()

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as file:
        os.chmod(path, 0o600)
        json.dump(value, file, sort_keys=True, separators=(",", ":"))
        file.write("\n")
