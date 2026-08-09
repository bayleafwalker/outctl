"""Deterministic, model-free mechanism benchmark for enablement gates."""

from __future__ import annotations

import asyncio
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from outctl.adapter import AdapterIdentity, AdapterMode, AdapterRequest, run_adapter
from outctl.projection import ProjectionLimits
from outctl.retrieval import RetrievalStatus, search_stream, verify_capture


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    script: str
    expected_exit: int
    marker: str | None = None
    exact_secret: str | None = None


def _cases(scale: int) -> tuple[BenchmarkCase, ...]:
    lines = max(100, scale)
    return (
        BenchmarkCase(
            "large-middle-marker",
            (
                "import sys\n"
                f"n={lines}\n"
                "for i in range(n):\n"
                " print('BENCHMARK-MIDDLE-MARKER' if i == n//2 else f'line {i:07d}')\n"
            ),
            0,
            marker="BENCHMARK-MIDDLE-MARKER",
        ),
        BenchmarkCase(
            "mixed-streams",
            (
                "import os\n"
                f"n={lines}\n"
                "for i in range(n):\n"
                " os.write(1, f'out {i:07d}\\n'.encode())\n"
                " os.write(2, f'err {i:07d}\\n'.encode())\n"
            ),
            0,
        ),
        BenchmarkCase(
            "failure-in-noise",
            (
                "import sys\n"
                f"n={lines}\n"
                "for i in range(n):\n"
                " print('RuntimeError: BENCHMARK-FAILURE' if i == n//2 else f'passing {i:07d}')\n"
                "raise SystemExit(7)\n"
            ),
            7,
            marker="BENCHMARK-FAILURE",
        ),
        BenchmarkCase(
            "registered-secret",
            "print('token=BENCHMARK-SECRET-VALUE')\n",
            0,
            exact_secret="BENCHMARK-SECRET-VALUE",
        ),
    )


async def run_mechanism_benchmark(
    spool_root: Path,
    *,
    repetitions: int = 1,
    scale: int = 20_000,
    max_projection_bytes: int = 4_096,
) -> dict[str, object]:
    if repetitions < 1 or repetitions > 100:
        raise ValueError("repetitions must be between 1 and 100")
    if scale < 100 or scale > 1_000_000:
        raise ValueError("scale must be between 100 and 1000000")
    spool_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    records: list[dict[str, object]] = []
    durations: list[float] = []
    total_raw_bytes = 0
    total_exposed_bytes = 0
    for repetition in range(1, repetitions + 1):
        for case in _cases(scale):
            started = time.monotonic()
            result = await run_adapter(
                AdapterRequest(
                    mode=AdapterMode.ENFORCE,
                    argv=(sys.executable, "-c", case.script),
                    policy_ref="mechanism-benchmark-v1",
                    policy_digest="sha256:" + "0" * 64,
                    identity=AdapterIdentity(host_id="local", harness="mechanism-benchmark"),
                    spool_root=spool_root,
                    projection_limits=ProjectionLimits(max_projection_bytes, 200, 1_024),
                    exact_values=(case.exact_secret,) if case.exact_secret else (),
                )
            )
            duration_ms = round((time.monotonic() - started) * 1_000, 3)
            if result.capture is None or result.envelope is None:
                raise RuntimeError("benchmark enforce execution produced no capture")
            capture = result.capture
            projection = result.envelope.projection
            verification = verify_capture(spool_root, capture.capture_id)
            marker_retrieved = None
            if case.marker is not None:
                marker_retrieved = any(
                    search_stream(
                        spool_root,
                        capture.capture_id,
                        stream,
                        case.marker,
                        max_matches=1,
                    ).matches
                    for stream in ("stdout", "stderr")
                )
            raw_bytes = capture.stdout_bytes + capture.stderr_bytes
            durations.append(duration_ms)
            total_raw_bytes += raw_bytes
            total_exposed_bytes += projection.bytes
            records.append(
                {
                    "case": case.name,
                    "repetition": repetition,
                    "capture_id": capture.capture_id,
                    "command_exit": result.command.exit_code,
                    "expected_exit": case.expected_exit,
                    "capture_status": result.envelope.capture.status,
                    "raw_bytes": raw_bytes,
                    "exposed_bytes": projection.bytes,
                    "raw_to_exposed_ratio": raw_bytes / projection.bytes
                    if projection.bytes
                    else None,
                    "projection_within_budget": projection.bytes <= max_projection_bytes,
                    "marker_retrieved_without_rerun": marker_retrieved,
                    "secret_absent_from_projection": (
                        case.exact_secret not in (projection.inline_text or "")
                        if case.exact_secret
                        else None
                    ),
                    "verification_status": verification.status.value,
                    "duration_ms": duration_ms,
                }
            )
    gates = {
        "all_commands_match_expected_exit": all(
            record["command_exit"] == record["expected_exit"] for record in records
        ),
        "all_captures_complete": all(
            record["capture_status"] == "COMPLETE" for record in records
        ),
        "all_projections_bounded": all(record["projection_within_budget"] for record in records),
        "all_markers_retrievable": all(
            record["marker_retrieved_without_rerun"] is not False for record in records
        ),
        "all_registered_secrets_redacted": all(
            record["secret_absent_from_projection"] is not False for record in records
        ),
        "all_captures_verify": all(
            record["verification_status"] == RetrievalStatus.AVAILABLE.value
            for record in records
        ),
    }
    return {
        "schema_version": "outctl.mechanism-benchmark/v1",
        "repetitions": repetitions,
        "scale": scale,
        "records": records,
        "summary": {
            "case_runs": len(records),
            "median_duration_ms": statistics.median(durations),
            "total_raw_bytes": total_raw_bytes,
            "total_exposed_bytes": total_exposed_bytes,
        },
        "gates": gates,
        "passed": all(gates.values()),
    }


def benchmark(spool_root: Path, **kwargs: int) -> dict[str, object]:
    """Synchronous CLI/test entry point."""
    return asyncio.run(run_mechanism_benchmark(spool_root, **kwargs))


def rollback_check() -> dict[str, object]:
    """Prove the break-glass flag selects bypass and creates no capture."""

    async def run(root: Path) -> dict[str, object]:
        from outctl.adapter import resolve_adapter_mode

        mode = resolve_adapter_mode(
            AdapterMode.ENFORCE,
            environ={"OUTCTL_ENABLED": "0", "OUTCTL_MODE": "enforce"},
        )
        result = await run_adapter(
            AdapterRequest(
                mode=mode,
                argv=(sys.executable, "-c", "raise SystemExit(0)"),
                policy_ref="rollback-check-v1",
                policy_digest="sha256:" + "0" * 64,
                identity=AdapterIdentity(host_id="local", harness="rollback-check"),
            )
        )
        captures = root / "captures"
        capture_count = len(list(captures.iterdir())) if captures.exists() else 0
        return {
            "schema_version": "outctl.rollback-check/v1",
            "mode": result.mode.value,
            "command_exit": result.command.exit_code,
            "capture_count": capture_count,
            "passed": (
                result.mode is AdapterMode.BYPASS
                and result.command.exit_code == 0
                and capture_count == 0
            ),
        }

    with tempfile.TemporaryDirectory(prefix="outctl-rollback-") as temporary:
        return asyncio.run(run(Path(temporary)))
