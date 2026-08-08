"""Construct typed, model-safe result envelopes from local capture metadata.

This module deliberately has no runner dependency beyond the ``CaptureResult``
value it is passed.  In particular, it does not execute (or re-execute) a
command while constructing an envelope.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from outctl.capture.runner import CaptureResult
from outctl.models import (
    CommandResultCapture,
    CommandResultCaptureSource,
    CommandResultCommand,
    CommandResultEnvelope,
    CommandResultInvocation,
    CommandResultProjection,
    CommandResultRetrieval,
)
from outctl.projection import ProjectionResult

_CAPTURE_STATUSES = {
    "COMPLETE": "COMPLETE",
    "TRUNCATED": "CAPTURE_TRUNCATED",
    "CAPTURE_FAILED": "CAPTURE_FAILED",
}
_RETRIEVAL_CAPABILITIES = ["inspect", "slice", "tail", "search", "verify"]


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_result_envelope(
    capture: CaptureResult,
    projection: ProjectionResult,
    invocation: CommandResultInvocation,
    *,
    policy_ref: str,
    policy_digest: str,
    mode: str = "auto",
    bindings: Mapping[str, str | None] | None = None,
    projection_id: str | None = None,
    capture_ref: str | None = None,
    deduplicated: bool = False,
    replicas: list[dict[str, object]] | None = None,
) -> CommandResultEnvelope:
    """Build an envelope from already-finalized capture and projection data.

    ``invocation`` is supplied by the execution owner because the capture
    engine intentionally does not invent wall-clock invocation metadata.
    """
    manifest_sha256 = _file_sha256(capture.path / "manifest.json")
    status = _CAPTURE_STATUSES[capture.capture_status]
    capture_ref = capture_ref or (
        f"outctl://capture/{capture.capture_id}/manifest/sha256/{manifest_sha256}"
    )
    projection_id = projection_id or f"sha256:{projection.sha256}"
    raw_bytes = capture.stdout_bytes + capture.stderr_bytes
    return CommandResultEnvelope(
        capture_ref=capture_ref,
        capture_id=capture.capture_id,
        bindings=dict(bindings or {}),
        invocation=invocation,
        command=CommandResultCommand(
            started=capture.command.started,
            exit_code=capture.command.exit_code,
            signal=capture.command.signal,
            timed_out=capture.command.timed_out,
            cancelled=capture.command.cancelled,
        ),
        capture=CommandResultCapture(
            status=status,
            stdout_bytes=capture.stdout_bytes,
            stderr_bytes=capture.stderr_bytes,
            truncated=status == "CAPTURE_TRUNCATED",
            manifest_sha256=manifest_sha256,
            stdout_sha256=capture.stdout_sha256,
            stderr_sha256=capture.stderr_sha256,
            event_count=capture.event_count,
            source=CommandResultCaptureSource(
                availability="local-only",
                host_id=invocation.host_id,
                path=str(capture.path),
            ),
        ),
        projection=CommandResultProjection(
            projection_id=projection_id,
            policy_ref=policy_ref,
            policy_digest=policy_digest,
            mode=mode,
            bytes=projection.bytes,
            lines=projection.lines,
            estimated_tokens=projection.estimated_tokens,
            lossy=projection.lossy,
            normalized=projection.normalized,
            deduplicated=deduplicated,
            redacted=projection.redacted,
            sha256=projection.sha256,
            inline_text=projection.text,
            token_estimator="utf8-bytes-div-4-v1",
        ),
        retrieval=CommandResultRetrieval(
            available=True,
            capabilities=list(_RETRIEVAL_CAPABILITIES),
        ),
        replicas=list(replicas or []),
        metrics={
            "raw_estimated_tokens": (raw_bytes + 3) // 4,
            "exposed_estimated_tokens": projection.estimated_tokens,
            "estimated_tokens_avoided": max(
                0, ((raw_bytes + 3) // 4) - projection.estimated_tokens
            ),
        },
    )
