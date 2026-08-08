"""Keep the experiment harness checks inside normal repository discovery."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
HARNESS = ROOT / "acceptance" / "codex_appservice_ab"


def test_offline_codex_exec_harness_suite() -> None:
    """The harness uses only a fake Codex executable and no cluster access."""
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "-v"],
        cwd=HARNESS,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
