#!/usr/bin/env python3
"""Create the W0 raw-free baseline reports.

This runner records only bounded metadata.  Command output and syscall trace
files are temporary host-local evidence and are never copied into the report.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "vuoro.outctl.w0-baseline/v1"
STARTUP_SCHEMA_VERSION = "vuoro.outctl.w0-startup-syscalls/v1"
ROADMAP_COMMIT = "1c8d6aeaa6f3526c50cb3626d6d7e301930f2b7d"


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _run(argv: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _percentile(samples: list[float], percentile: float) -> float:
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _parse_syscalls(path: Path) -> dict[str, int | float]:
    """Parse the data rows emitted by ``strace -c``.

    The summary columns are ``% time``, ``seconds``, ``usecs/call``,
    ``calls``, ``errors``, and ``syscall``.  In particular, the first column
    is a percentage and must not be reported as elapsed seconds.
    """

    calls = 0
    errors = 0
    elapsed = 0.0
    pattern = re.compile(
        r"^\s*[0-9.]+\s+(?P<seconds>[0-9.]+)\s+\d+\s+"
        r"(?P<calls>\d+)(?:\s+(?P<errors>\d+))?\s+(?P<syscall>\S+)\s*$"
    )
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if match is None or match.group("syscall") == "total":
            continue
        elapsed += float(match.group("seconds"))
        calls += int(match.group("calls"))
        errors += int(match.group("errors") or 0)
    return {"syscall_calls": calls, "syscall_errors": errors, "syscall_seconds": elapsed}


def _startup_probe(
    name: str,
    argv: list[str],
    *,
    env: dict[str, str],
    trace_dir: Path,
    repetitions: int,
) -> dict[str, object]:
    timings: list[float] = []
    syscall_records: list[dict[str, int | float]] = []
    syscall_status = "available" if shutil.which("strace") else "unavailable"
    syscall_unavailable_reason: str | None = (
        None if syscall_status == "available" else "strace is not installed"
    )
    for index in range(repetitions):
        trace = trace_dir / f"{name}-{index}.txt"
        command = ["strace", "-qq", "-f", "-c", "-o", str(trace), *argv]
        started = time.perf_counter_ns()
        result = _run(command, env=env) if syscall_status == "available" else None
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        if (
            result is not None
            and result.returncode != 0
            and ("Operation not permitted" in result.stderr or "ptrace" in result.stderr)
        ):
            syscall_status = "unavailable"
            syscall_unavailable_reason = "ptrace denied by execution sandbox"
            trace.unlink(missing_ok=True)
            started = time.perf_counter_ns()
            result = _run(argv, env=env)
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        elif result is None:
            started = time.perf_counter_ns()
            result = _run(argv, env=env)
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        if result.returncode != 0:
            raise RuntimeError(f"startup probe {name} failed with {result.returncode}")
        timings.append(round(elapsed_ms, 3))
        if syscall_status == "available" and trace.exists():
            syscall_records.append(_parse_syscalls(trace))
        trace.unlink(missing_ok=True)
    if syscall_status == "available" and len(syscall_records) != repetitions:
        syscall_status = "unavailable"
        syscall_unavailable_reason = "strace did not produce one summary per sample"
    calls = [int(record["syscall_calls"]) for record in syscall_records]
    errors = [int(record["syscall_errors"]) for record in syscall_records]
    return {
        "command": argv,
        "fresh_processes": repetitions,
        "wall_time_ms": {
            "min": min(timings),
            "p50": round(_percentile(timings, 0.50), 3),
            "p95": round(_percentile(timings, 0.95), 3),
            "p99": round(_percentile(timings, 0.99), 3),
            "max": max(timings),
            "samples": timings,
        },
        "syscalls": (
            {
                "status": "available",
                "calls_min": min(calls),
                "calls_median": statistics.median(calls),
                "calls_max": max(calls),
                "errors_max": max(errors),
                "samples": syscall_records,
            }
            if syscall_status == "available"
            else {"status": syscall_status, "reason": syscall_unavailable_reason}
        ),
    }


def _profile_command(
    label: str,
    argv: list[str],
    *,
    env: dict[str, str],
    repetitions: int,
) -> dict[str, object]:
    samples: list[float] = []
    records: list[dict[str, object]] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        result = _run(argv, env=env)
        samples.append(round((time.perf_counter_ns() - started) / 1_000_000, 3))
        if result.returncode != 0:
            raise RuntimeError(f"profile {label} failed with {result.returncode}")
        payload = json.loads(result.stdout)
        envelope = payload["envelope"]
        capture = envelope["capture"]
        projection = envelope["projection"]
        records.append(
            {
                "capture_id": envelope["capture_id"],
                "manifest_sha256": capture["manifest_sha256"],
                "capture_status": capture["status"],
                "command_exit": envelope["command"]["exit_code"],
                "raw_bytes": capture["stdout_bytes"] + capture["stderr_bytes"],
                "exposed_bytes": projection["bytes"],
                "raw_estimated_tokens": envelope["metrics"]["raw_estimated_tokens"],
                "exposed_estimated_tokens": envelope["metrics"]["exposed_estimated_tokens"],
                "projection_lossy": projection["lossy"],
            }
        )
    first = records[0]
    return {
        "label": label,
        "capture_id": first["capture_id"],
        "manifest_sha256": first["manifest_sha256"],
        "capture_ids": [record["capture_id"] for record in records],
        "manifest_sha256s": [record["manifest_sha256"] for record in records],
        "capture_count": repetitions,
        "capture_status": first["capture_status"],
        "all_captures_complete": all(
            record["capture_status"] == "COMPLETE" for record in records
        ),
        "command_exit": first["command_exit"],
        "all_commands_succeeded": all(record["command_exit"] == 0 for record in records),
        "raw_bytes": first["raw_bytes"],
        "exposed_bytes": first["exposed_bytes"],
        "raw_estimated_tokens": first["raw_estimated_tokens"],
        "exposed_estimated_tokens": first["exposed_estimated_tokens"],
        "projection_lossy": first["projection_lossy"],
        "wall_time_ms": {
            "min": min(samples),
            "p50": round(_percentile(samples, 0.50), 3),
            "p95": round(_percentile(samples, 0.95), 3),
            "p99": round(_percentile(samples, 0.99), 3),
            "max": max(samples),
            "samples": samples,
        },
    }


def _metadata_only_benchmark(spool: Path, env: dict[str, str]) -> dict[str, object]:
    command = [
        sys.executable,
        "-m",
        "outctl.cli",
        "benchmark",
        "--spool-root",
        str(spool),
        "--repetitions",
        "1",
        "--scale",
        "20000",
        "--max-projection-bytes",
        "4096",
    ]
    result = _run(command, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"mechanism benchmark failed with {result.returncode}")
    value = json.loads(result.stdout)
    records = []
    for record in value["records"]:
        records.append(
            {
                key: record[key]
                for key in (
                    "case",
                    "repetition",
                    "capture_id",
                    "command_exit",
                    "expected_exit",
                    "capture_status",
                    "raw_bytes",
                    "exposed_bytes",
                    "raw_to_exposed_ratio",
                    "projection_within_budget",
                    "marker_retrieved_without_rerun",
                    "secret_absent_from_projection",
                    "verification_status",
                    "duration_ms",
                )
            }
        )
    return {
        "schema_version": value["schema_version"],
        "repetitions": value["repetitions"],
        "scale": value["scale"],
        "summary": value["summary"],
        "gates": value["gates"],
        "passed": value["passed"],
        "records": records,
    }


def _policy_digest(env: dict[str, str]) -> str:
    probe = (
        "from outctl.policy import load_policy_set, resolve_and_digest; "
        "p=load_policy_set('config/output-policies.example.yaml'); "
        "print(resolve_and_digest(p, 'interactive-default-v1')[1])"
    )
    result = _run([sys.executable, "-c", probe], env=env)
    if result.returncode != 0:
        raise RuntimeError("policy digest probe failed")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "verification" / "w0")
    parser.add_argument("--spool-root", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--installed-python", type=Path)
    parser.add_argument("--installed-pythonpath", type=str)
    parser.add_argument("--installed-artifact", type=Path)
    parser.add_argument("--source-pythonpath", type=str)
    parser.add_argument("--uv-environment", type=Path)
    parser.add_argument("--uv-cache", type=Path)
    args = parser.parse_args()

    if args.repetitions < 5:
        raise SystemExit("at least five fresh processes are required")
    base_env = os.environ.copy()
    base_env["PYTHONUNBUFFERED"] = "1"
    base_env.pop("PYTHONPATH", None)
    source_env = dict(base_env)
    source_env["PYTHONPATH"] = args.source_pythonpath or str(ROOT / "src")

    installed_env = dict(base_env)
    if args.installed_pythonpath:
        installed_env["PYTHONPATH"] = args.installed_pythonpath
    installed_python = str(args.installed_python or sys.executable)
    installed_command = [installed_python, "-m", "outctl.cli", "--help"]

    uv_env = dict(installed_env)
    uv_command = [
        "uv",
        "run",
        "--offline",
        "--no-project",
        "--python",
        sys.executable,
        "python",
        "-m",
        "outctl.cli",
        "--help",
    ]
    if args.uv_environment:
        uv_env["UV_PROJECT_ENVIRONMENT"] = str(args.uv_environment)
    if args.uv_cache:
        uv_env["UV_CACHE_DIR"] = str(args.uv_cache)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.spool_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    policy_digest = _policy_digest(source_env)
    with tempfile.TemporaryDirectory(prefix="outctl-w0-startup-", dir="/tmp") as trace_root:
        trace_dir = Path(trace_root)
        startup = {
            "schema_version": STARTUP_SCHEMA_VERSION,
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "strace": shutil.which("strace"),
            "syscall_parser": {
                "format": "strace -c summary",
                "seconds_column": "seconds",
                "excluded_rows": ["total"],
            },
            "probes": {
                "direct-source": _startup_probe(
                    "direct-source",
                    [sys.executable, "-m", "outctl.cli", "--help"],
                    env=source_env,
                    trace_dir=trace_dir,
                    repetitions=args.repetitions,
                ),
                "installed": _startup_probe(
                    "installed",
                    installed_command,
                    env=installed_env,
                    trace_dir=trace_dir,
                    repetitions=args.repetitions,
                ),
                "uv-run": _startup_probe(
                    "uv-run",
                    uv_command,
                    env=uv_env,
                    trace_dir=trace_dir,
                    repetitions=args.repetitions,
                ),
            },
        }
    _write_json(args.output_dir / "startup-syscalls.json", startup)

    profiles: dict[str, dict[str, object]] = {}
    profile_commands = {
        "direct-source": ([sys.executable, "-m", "outctl.cli"], source_env),
        "installed": ([installed_python, "-m", "outctl.cli"], installed_env),
        "uv-run": (
            [
                "uv",
                "run",
                "--offline",
                "--no-project",
                "--python",
                sys.executable,
                "python",
                "-m",
                "outctl.cli",
            ],
            uv_env,
        ),
    }
    for runtime, (base_command, runtime_env) in profile_commands.items():
        runtime_name = runtime if isinstance(runtime, str) else runtime[0]
        for profile_name, code in (("empty", "pass"), ("one-line", "print('x')")):
            command = [
                *base_command,
                "run",
                "--mode",
                "enforce",
                "--policy-digest",
                policy_digest,
                "--spool-root",
                str(args.spool_root),
                "--",
                sys.executable,
                "-c",
                code,
            ]
            profiles[f"{runtime_name}/{profile_name}"] = _profile_command(
                f"{runtime_name}/{profile_name}",
                command,
                env=runtime_env,
                repetitions=args.repetitions,
            )

    benchmark = _metadata_only_benchmark(args.spool_root, installed_env)
    one_line = profiles["installed/one-line"]
    projection_1000 = {
        "command_count": 1000,
        "basis": (
            "linear projection of the installed one-line profile; repeated profile "
            "samples are not 1,000 executions"
        ),
        "executed_commands": one_line["capture_count"],
        "raw_bytes": one_line["raw_bytes"] * 1000,
        "exposed_bytes": one_line["exposed_bytes"] * 1000,
        "raw_estimated_tokens": one_line["raw_estimated_tokens"] * 1000,
        "exposed_estimated_tokens": one_line["exposed_estimated_tokens"] * 1000,
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "repository": {
            "commit": _run(["git", "rev-parse", "HEAD"]).stdout.strip(),
            "branch": _run(["git", "branch", "--show-current"]).stdout.strip(),
            "base_ref": "origin/main",
            "roadmap_materialized_in_worktree": (ROOT / "docs" / "MIGRATION_ROADMAP.md").exists(),
        },
        "installation": {
            "installed_python": installed_python,
            "artifact": (
                {
                    "path": str(args.installed_artifact.resolve()),
                    "sha256": _sha256(args.installed_artifact),
                }
                if args.installed_artifact
                else None
            ),
        },
        "governing_baseline": {
            "available_documents": [
                "AGENTS.md",
                "docs/DESIGN.md",
                "docs/THREAT-MODEL.md",
                "acceptance/SCENARIOS.md",
                "IMPLEMENTATION_HANDOFF.md",
                "docs/IMPLEMENTATION_PLAN.md",
                "outctl.dispatch.json",
            ],
            "roadmap_commit": ROADMAP_COMMIT,
            "roadmap_materialized_in_worktree": False,
            "risk_surfaces": ["process-semantics", "evidence-integrity-and-redaction"],
        },
        "policy_digest": policy_digest,
        "startup": startup,
        "profiles": profiles,
        "projection_1000_commands": projection_1000,
        "benchmark": benchmark,
        "raw_free": True,
        "raw_output_in_report": False,
    }
    _write_json(args.output_dir / "baseline-report.json", report)

    references = {
        "schema_version": "vuoro.outctl.w0-host-local-references/v1",
        "classification": "local-only",
        "portable": False,
        "host": socket.gethostname(),
        "spool_root": str(args.spool_root.resolve()),
        "spool_mode": oct(args.spool_root.stat().st_mode & 0o777),
        "manifest_references": [
            {
                "label": record["case"],
                "capture_id": record["capture_id"],
                "manifest": str(
                    args.spool_root / "captures" / record["capture_id"] / "manifest.json"
                ),
                "manifest_sha256": _sha256(
                    args.spool_root / "captures" / record["capture_id"] / "manifest.json"
                ),
                "raw_streams": "host-local; not included in Git",
            }
            for record in benchmark["records"]
        ]
        + [
            {
                "label": label,
                "capture_id": capture_id,
                "manifest": str(
                    args.spool_root / "captures" / capture_id / "manifest.json"
                ),
                "manifest_sha256": manifest_sha256,
                "raw_streams": "host-local; not included in Git",
            }
            for label, record in profiles.items()
            for capture_id, manifest_sha256 in zip(
                record["capture_ids"], record["manifest_sha256s"], strict=True
            )
        ],
        "raw_free": True,
        "raw_output_in_report": False,
    }
    _write_json(args.output_dir / "host-local-references.json", references)
    _write_json(
        args.output_dir / "golden-metadata.json",
        {
            "schema_version": "vuoro.outctl.w0-golden-metadata/v1",
            "policy_digest": report["policy_digest"],
            "benchmark_summary": benchmark["summary"],
            "startup_percentiles": {
                name: value["wall_time_ms"]
                for name, value in startup["probes"].items()
            },
            "profiles": profiles,
            "projection_1000_commands": projection_1000,
            "gates": benchmark["gates"],
            "capture_ids": [
                record["capture_id"] for record in benchmark["records"]
            ]
            + [
                capture_id
                for record in profiles.values()
                for capture_id in record["capture_ids"]
            ],
            "raw_free": True,
            "frozen_at_commit": report["repository"]["commit"],
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
