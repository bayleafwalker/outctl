from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import jsonschema

from outctl.capture import capture_command
from outctl.envelope import build_result_envelope
from outctl.models import CommandResultEnvelope, CommandResultInvocation
from outctl.projection import project_bytes


def test_build_result_envelope_roundtrips_existing_capture_metadata(tmp_path: Path) -> None:
    capture = asyncio.run(
        capture_command([sys.executable, "-c", "print('hello')"], tmp_path, max_bytes=1024)
    )
    projection = project_bytes(b"hello\n")
    envelope = build_result_envelope(
        capture,
        projection,
        CommandResultInvocation(
            argv_display=["python", "-c", "print('hello')"],
            shell=False,
            cwd=str(tmp_path),
            host_id="test-host",
            harness="pytest",
            started_at="2026-08-08T00:00:00Z",
        ),
        policy_ref="test-policy",
        policy_digest="sha256:" + "0" * 64,
    )

    roundtrip = CommandResultEnvelope.from_dict(envelope.to_dict())
    assert roundtrip == envelope
    assert envelope.capture.status == "COMPLETE"
    assert envelope.command.exit_code == 0
    assert envelope.projection.inline_text == "hello\n"
    assert envelope.retrieval.capabilities == ["inspect", "slice", "tail", "search", "verify"]

    schema = __import__("json").loads(
        (Path(__file__).parents[1] / "schemas/command-result-envelope.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(envelope.to_dict())
