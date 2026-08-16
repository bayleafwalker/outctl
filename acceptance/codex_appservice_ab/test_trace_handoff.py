from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from build_trace_handoff import build


class TraceHandoffTests(unittest.TestCase):
    def test_archive_uses_relative_checksums_and_excludes_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_root = root / "run"
            private = run_root / "private" / "pair-001" / "A"
            private.mkdir(parents=True)
            events = private / "events.jsonl"
            events.write_text('{"type":"thread.started"}\n')
            (run_root / "private" / "pair-001" / "shell-home-A").mkdir()
            (run_root / "private" / "pair-001" / "shell-home-A" / "auth.json").write_text(
                "should-not-ship"
            )
            (run_root / "private" / "pair-001" / "tooling-A").mkdir()
            (run_root / "private" / "pair-001" / "tooling-A" / "runner").write_text(
                "local state"
            )
            (run_root / "private" / "pair-001" / "codex-home-A").mkdir()
            (run_root / "private" / "pair-001" / "codex-home-A" / "auth.json").write_text(
                "must-not-ship"
            )
            (run_root / "report.json").write_text(
                json.dumps(
                    {
                        "pairs": [
                            {
                                "arms": {
                                    "A": {
                                        "private_artifacts": {"events": str(events)}
                                    }
                                }
                            }
                        ]
                    }
                )
            )
            observer = root / "trace_handler.py"
            observer.write_text("observer\n")
            archive_path = root / "handoff.tar.gz"
            build(run_root, archive_path, observer)

            with tarfile.open(archive_path, "r:gz") as archive:
                names = set(archive.getnames())
                archive.extractall(root / "unpacked", filter="data")
            unpacked = root / "unpacked"
            self.assertIn("SHA256SUMS", names)
            self.assertIn("private/pair-001/A/events.jsonl", names)
            self.assertNotIn("private/pair-001/shell-home-A/auth.json", names)
            self.assertNotIn("private/pair-001/tooling-A/runner", names)
            self.assertNotIn("private/pair-001/codex-home-A/auth.json", names)
            report = json.loads((unpacked / "report.json").read_text())
            self.assertEqual(
                report["pairs"][0]["arms"]["A"]["private_artifacts"]["archive_relative_paths"][
                    "events"
                ],
                "private/pair-001/A/events.jsonl",
            )
            checksum_line = next(
                line
                for line in (unpacked / "SHA256SUMS").read_text().splitlines()
                if line.endswith("  private/pair-001/A/events.jsonl")
            )
            expected = hashlib.sha256(events.read_bytes()).hexdigest()
            self.assertTrue(checksum_line.startswith(expected + "  "))


if __name__ == "__main__":
    unittest.main()
