"""Deterministic semantic projections for known, high-volume command families."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from outctl.projection import ProjectionLimits, ProjectionResult, project_bytes

POD_HEALTH_ADAPTER = "kubernetes.pod-health/v1"
_POD_HEALTH_STATUSES = (
    "Error",
    "OOMKilled",
    "Pending",
    "CrashLoopBackOff",
    "ImagePullBackOff",
)
_MAX_SEMANTIC_LINE_BYTES = 1 * 1024 * 1024
_MAX_ANOMALOUS_ROW_BYTES = 512
_SEMANTIC_FULL_IF_UNDER_BYTES = 16 * 1024


@dataclass
class _PodHealthAccumulator:
    header_seen: bool = False
    parse_failed: bool = False
    total_rows: int = 0
    status_counts: dict[str, int] | None = None
    anomalous_rows: list[str] | None = None
    anomalous_rows_dropped: int = 0
    anomalous_rows_clipped: int = 0

    def __post_init__(self) -> None:
        self.status_counts = {}
        self.anomalous_rows = []

    def add_row(self, line: str) -> None:
        assert self.status_counts is not None
        assert self.anomalous_rows is not None
        tokens = line.split()
        if len(tokens) < 4:
            self.parse_failed = True
            return
        self.total_rows += 1
        status = tokens[3][:128]
        if status in self.status_counts or len(self.status_counts) < 128:
            self.status_counts[status] = self.status_counts.get(status, 0) + 1
        else:
            self.status_counts["<other>"] = self.status_counts.get("<other>", 0) + 1
        if status in _POD_HEALTH_STATUSES:
            row = f"{tokens[0][:128]}/{tokens[1][:256]} status={status} ready={tokens[2][:64]}"
            if len(row.encode("utf-8")) > _MAX_ANOMALOUS_ROW_BYTES:
                row = (
                    row.encode("utf-8")[: _MAX_ANOMALOUS_ROW_BYTES - 25]
                    .decode("utf-8", errors="ignore")
                    + " [... row clipped ...]"
                )
                self.anomalous_rows_clipped += 1
            if len(self.anomalous_rows) < 4096:
                self.anomalous_rows.append(row)
            else:
                self.anomalous_rows_dropped += 1


def _line_bytes(chunks: Iterable[bytes]) -> Iterable[bytes | None]:
    """Yield bounded lines, using ``None`` for an overlong line."""
    pending = bytearray()
    skipping = False
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("semantic projection chunks must be bytes")
        for value in chunk:
            if skipping:
                if value == 10:
                    skipping = False
                continue
            if value == 10:
                yield bytes(pending).rstrip(b"\r")
                pending.clear()
                continue
            pending.append(value)
            if len(pending) > _MAX_SEMANTIC_LINE_BYTES:
                pending.clear()
                skipping = True
                yield None
    if pending and not skipping:
        yield bytes(pending).rstrip(b"\r")


def _fits(text: str, limits: ProjectionLimits) -> bool:
    encoded = text.encode("utf-8")
    return (
        len(encoded) <= limits.max_bytes
        and len(encoded.splitlines()) <= limits.max_lines
        and (len(encoded) + 3) // 4 <= limits.max_estimated_tokens
    )


def _summary_text(accumulator: _PodHealthAccumulator, limits: ProjectionLimits) -> tuple[str, int]:
    assert accumulator.status_counts is not None
    assert accumulator.anomalous_rows is not None
    counts = ", ".join(
        f"{status}={count}" for status, count in sorted(accumulator.status_counts.items())
    ) or "none"
    predicates = ", ".join(
        f"{status}={accumulator.status_counts.get(status, 0)}"
        for status in _POD_HEALTH_STATUSES
    )
    total_anomalies = sum(
        accumulator.status_counts.get(status, 0) for status in _POD_HEALTH_STATUSES
    )
    lines = [
        "Complete health scan; compact evidence view.",
        "scan_coverage: complete",
        f"total_rows: {accumulator.total_rows}",
        f"status_counts: {counts}",
        f"health_predicates: {predicates}",
        f"anomalous_rows_total: {total_anomalies}",
        f"routine_rows_omitted: {max(0, accumulator.total_rows - total_anomalies)}",
        "anomalous_rows:",
    ]
    shown = 0
    for row in accumulator.anomalous_rows:
        candidate = "\n".join([*lines, f"- {row}", ""])
        if not _fits(candidate, limits):
            break
        lines.append(f"- {row}")
        shown += 1
    lines.append(f"anomalous_rows_shown: {shown}")
    if accumulator.anomalous_rows_dropped:
        lines.append(f"anomalous_rows_not_buffered: {accumulator.anomalous_rows_dropped}")
    if accumulator.anomalous_rows_clipped:
        lines.append(f"anomalous_rows_clipped: {accumulator.anomalous_rows_clipped}")
    text = "\n".join(lines) + "\n"
    return text, shown


def project_pod_health(
    chunks: Iterable[bytes],
    *,
    limits: ProjectionLimits,
    exact_values: Iterable[bytes | str] = (),
    exact_redaction_rules: Mapping[str, Iterable[bytes | str]] | None = None,
) -> ProjectionResult | None:
    """Return a complete pod-health summary for a wide tabular pod listing.

    ``None`` means the input was not confidently recognized as the supported
    ``kubectl get pods -A -o wide`` table; callers must use the generic bounded
    projection in that case.  The parser retains only bounded per-row evidence
    and aggregate counts, never the complete command output.
    """
    accumulator = _PodHealthAccumulator()
    first_content_seen = False
    for raw_line in _line_bytes(chunks):
        if raw_line is None:
            accumulator.parse_failed = True
            continue
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        folded = line.casefold()
        if not first_content_seen:
            first_content_seen = True
            if folded.startswith("no resources found"):
                accumulator.header_seen = True
                break
            header = line.split()
            if len(header) < 4 or header[0].casefold() not in {"namespace", "name"}:
                return None
            if "status" not in {value.casefold() for value in header}:
                return None
            accumulator.header_seen = True
            continue
        if accumulator.header_seen:
            accumulator.add_row(line)
    if not accumulator.header_seen or accumulator.parse_failed:
        return None

    text, shown = _summary_text(accumulator, limits)
    projected = project_bytes(
        text.encode("utf-8"),
        exact_values=exact_values,
        exact_redaction_rules=exact_redaction_rules,
        limits=limits,
    )
    assert accumulator.status_counts is not None
    assert accumulator.anomalous_rows is not None
    total_anomalies = sum(
        accumulator.status_counts.get(status, 0) for status in _POD_HEALTH_STATUSES
    )
    decision_complete = (
        not projected.lossy
        and shown == total_anomalies
        and accumulator.anomalous_rows_dropped == 0
        and accumulator.anomalous_rows_clipped == 0
    )
    annotations: dict[str, object] = {
        "presentation": "semantic-complete" if decision_complete else "semantic-bounded",
        "semantic_adapter": POD_HEALTH_ADAPTER,
        "scan_coverage": "complete",
        "decision_complete": decision_complete,
        "total_rows": accumulator.total_rows,
        "status_counts": dict(sorted(accumulator.status_counts.items())),
        "health_predicates": {
            status: accumulator.status_counts.get(status, 0) for status in _POD_HEALTH_STATUSES
        },
        "anomalous_rows_total": total_anomalies,
        "anomalous_rows_shown": shown,
        "routine_rows_omitted": max(0, accumulator.total_rows - total_anomalies),
        "anomalous_rows_clipped": accumulator.anomalous_rows_clipped,
    }
    return ProjectionResult(
        output=projected.output,
        text=projected.text,
        bytes=projected.bytes,
        lines=projected.lines,
        estimated_tokens=projected.estimated_tokens,
        lossy=projected.lossy,
        normalized=projected.normalized,
        redacted=projected.redacted,
        sha256=projected.sha256,
        gap_marker=projected.gap_marker,
        redaction_rules=projected.redaction_rules,
        annotations=annotations,
    )


def semantic_full_if_under_bytes() -> int:
    """Return the adaptive threshold below which exact output is preferable."""
    return _SEMANTIC_FULL_IF_UNDER_BYTES


def detect_semantic_adapter(argv: Sequence[str]) -> str | None:
    """Recognize a runner-pinned all-namespaces pod list without shell parsing."""
    if not argv:
        return None
    tokens = list(argv)
    if Path(tokens[0]).name.casefold() == "kubectl":
        tokens = tokens[1:]
    logical: list[str] = []
    skip = False
    identity_flags = {
        "--kubeconfig",
        "--context",
        "--cluster",
        "--user",
        "--server",
        "--token",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--tls-server-name",
    }
    for token in tokens:
        if skip:
            skip = False
            continue
        if token in identity_flags:
            skip = True
            continue
        logical.append(token)
    if not logical or logical[0].casefold() != "get":
        return None
    positionals = [token for token in logical[1:] if not token.startswith("-")]
    all_namespaces = "-A" in logical or "--all-namespaces" in logical
    if all_namespaces and positionals and positionals[0].casefold() in {"pod", "pods"}:
        return POD_HEALTH_ADAPTER
    return None
