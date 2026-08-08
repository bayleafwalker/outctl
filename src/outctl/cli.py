"""Command-line entry point.

The runtime commands deliberately remain unavailable until their corresponding
implementation slice and acceptance gates land.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from outctl import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="outctl",
        description="Bounded, recoverable command-output tooling (implementation scaffold)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

