"""Deterministic, bounded projection of captured byte streams.

This module operates on supplied bytes only.  It does not read captures or
rerun commands, and it keeps at most the configured projection budget in
memory.
"""

from __future__ import annotations

import codecs
import hashlib
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

OMISSION_MARKER = "[... output omitted ...]"
LINE_CLIPPED_MARKER = " [... line clipped ...]"
_PROCESSING_CHUNK_BYTES = 64 * 1024
_MAX_REPRESENTATIVE_BYTES = 4 * 1024
_FAILURE_CONTEXT_BEFORE = 3
_FAILURE_CONTEXT_AFTER = 4


def _is_failure_anchor(text: str) -> bool:
    """Return whether a normalized record is useful failure evidence."""
    lowered = text.casefold()
    return any(
        anchor in lowered
        for anchor in (
            "traceback",
            "exception",
            "error",
            "failure",
            "failed",
            "fatal",
            "assertionerror",
        )
    )


@dataclass(frozen=True)
class ProjectionLimits:
    """Hard limits for model-facing projection output."""

    max_bytes: int
    max_lines: int
    max_estimated_tokens: int

    def __post_init__(self) -> None:
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if self.max_lines <= 0:
            raise ValueError("max_lines must be positive")
        if self.max_estimated_tokens <= 0:
            raise ValueError("max_estimated_tokens must be positive")


@dataclass(frozen=True)
class ProjectionResult:
    """A binary-safe projection and its deterministic metadata."""

    output: bytes
    text: str
    bytes: int
    lines: int
    estimated_tokens: int
    lossy: bool
    normalized: bool
    redacted: bool
    sha256: str
    gap_marker: str | None
    redaction_rules: tuple[RedactionRule, ...] = ()
    annotations: dict[str, object] | None = None

    @property
    def digest(self) -> str:
        """Return the algorithm-qualified projection digest."""
        return f"sha256:{self.sha256}"

    @property
    def omitted(self) -> bool:
        """Return whether a budget caused output omission."""
        return self.gap_marker is not None


@dataclass(frozen=True)
class RedactionRule:
    """An applied redaction rule, deliberately without a matched value."""

    identifier: str
    count: int


class _ExactRedactor:
    """Streaming byte redactor with deterministic longest-match precedence."""

    def __init__(
        self, rules: Iterable[tuple[str, bytes]], replacement: bytes
    ) -> None:
        values_by_rule: dict[bytes, str] = {}
        for identifier, value in rules:
            if not identifier:
                raise ValueError("redaction rule identifiers must not be empty")
            if not value:
                raise ValueError("exact redaction values must not be empty")
            existing = values_by_rule.get(value)
            # Identical values in separate rules are assigned deterministically
            # without retaining or emitting the sensitive value.
            if existing is None or identifier < existing:
                values_by_rule[value] = identifier
        if any(not value for value in values_by_rule):
            raise ValueError("exact redaction values must not be empty")
        self._values = tuple(
            sorted(
                values_by_rule,
                key=lambda value: (-len(value), value, values_by_rule[value]),
            )
        )
        self._rule_for_value = values_by_rule
        self._counts: dict[str, int] = {}
        self._max_length = max((len(value) for value in self._values), default=1)
        self._replacement = replacement
        self._pending = bytearray()
        self.redacted = False

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        if not self._values:
            return chunk

        data = bytes(self._pending) + chunk
        self._pending.clear()
        output = bytearray()
        cursor = 0

        while cursor < len(data) and (final or len(data) - cursor >= self._max_length):
            match = next(
                (value for value in self._values if data.startswith(value, cursor)),
                None,
            )
            if match is not None:
                output.extend(self._replacement)
                cursor += len(match)
                self.redacted = True
                identifier = self._rule_for_value[match]
                self._counts[identifier] = self._counts.get(identifier, 0) + 1
            else:
                output.append(data[cursor])
                cursor += 1

        self._pending.extend(data[cursor:])

        return bytes(output)

    @property
    def rules(self) -> tuple[RedactionRule, ...]:
        """Return applied rule identifiers and counts in stable order."""
        return tuple(
            RedactionRule(identifier, count)
            for identifier, count in sorted(self._counts.items())
        )


def _neutralize_controls(text: str) -> tuple[str, bool]:
    """Render control characters visibly so ANSI cannot affect a terminal."""
    output: list[str] = []
    changed = False
    for character in text:
        codepoint = ord(character)
        if character == "\n":
            output.append(character)
        elif character == "\r":
            output.append("\\r")
            changed = True
        elif character == "\t":
            output.append("\\t")
            changed = True
        elif codepoint < 0x20 or codepoint == 0x7F:
            output.append(f"\\x{codepoint:02x}")
            changed = True
        elif unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            width = 4 if codepoint <= 0xFFFF else 8
            output.append(f"\\u{codepoint:0{width}x}")
            changed = True
        else:
            output.append(character)
    return "".join(output), changed


def _neutralize_character(character: str) -> tuple[str, bool]:
    """Return one safe display character, except record separators."""
    codepoint = ord(character)
    if character in {"\n", "\r"}:
        return character, False
    if character == "\t":
        return "\\t", True
    if codepoint < 0x20 or codepoint == 0x7F:
        return f"\\x{codepoint:02x}", True
    if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
        width = 4 if codepoint <= 0xFFFF else 8
        return f"\\u{codepoint:0{width}x}", True
    return character, False


class _LogicalRecord:
    """A bounded representation of one line or carriage-return update."""

    def __init__(self, representative_bytes: int) -> None:
        self._representative_bytes = representative_bytes
        self._characters: list[str] = []
        self._byte_count = 0
        self._total_bytes = 0
        self._digest = hashlib.sha256()
        self._clipped = False

    def add(self, text: str) -> None:
        encoded = text.encode("utf-8")
        self._digest.update(encoded)
        self._total_bytes += len(encoded)
        if self._clipped:
            return
        if self._byte_count + len(encoded) > self._representative_bytes:
            self._clipped = True
            return
        self._characters.append(text)
        self._byte_count += len(encoded)

    @property
    def identity(self) -> tuple[int, str]:
        """Return a bounded-memory equality key for normalized record content."""
        return self._total_bytes, self._digest.hexdigest()

    @property
    def empty(self) -> bool:
        return self._total_bytes == 0

    @property
    def clipped(self) -> bool:
        return self._clipped

    def render(self) -> str:
        text = "".join(self._characters)
        return f"{text}{LINE_CLIPPED_MARKER}" if self._clipped else text


class _ProjectionNormalizer:
    """Stream logical records into a collector with repeat/progress collapse."""

    def __init__(self, collector: _PrefixCollector, limits: ProjectionLimits) -> None:
        self._collector = collector
        # Reserve room for the per-line marker so a giant logical line is
        # explicitly clipped before it can consume the projection budget, and
        # for the ordinary omission marker that records the resulting loss.
        budget = min(limits.max_bytes, limits.max_estimated_tokens * 4)
        reserved = len(LINE_CLIPPED_MARKER.encode()) + 1 + len(OMISSION_MARKER.encode())
        self._representative_bytes = max(1, min(_MAX_REPRESENTATIVE_BYTES, budget - reserved))
        self._current = _LogicalRecord(self._representative_bytes)
        self._raw_line = 0
        self._repeat_record: _LogicalRecord | None = None
        self._repeat_count = 0
        self._repeat_start = 0
        self._progress_first: _LogicalRecord | None = None
        self._progress_last: _LogicalRecord | None = None
        self._progress_count = 0
        self.controls_changed = False
        self.line_clipped = False
        self.repetition_collapsed = False

    def feed(self, text: str) -> None:
        for character in text:
            if character == "\r":
                self.controls_changed = True
                self._finish_progress()
            elif character == "\n":
                self._finish_line()
            else:
                display, changed = _neutralize_character(character)
                self.controls_changed = self.controls_changed or changed
                self._current.add(display)

    def finish(self) -> None:
        if not self._current.empty:
            self._finish_line(terminated=False)
        self._flush_progress()
        self._flush_repetition()

    def _finish_progress(self) -> None:
        record = self._current
        self._current = _LogicalRecord(self._representative_bytes)
        if record.empty:
            return
        if self._progress_first is None:
            self._progress_first = record
        self._progress_last = record
        self._progress_count += 1

    def _finish_line(self, *, terminated: bool = True) -> None:
        self._flush_progress()
        self._raw_line += 1
        record = self._current
        self._current = _LogicalRecord(self._representative_bytes)
        if not terminated:
            self._flush_repetition()
            self.line_clipped = self.line_clipped or record.clipped
            self._collector.add(
                record.render(), failure_anchor=_is_failure_anchor(record.render())
            )
            return
        if self._repeat_record is not None and record.identity == self._repeat_record.identity:
            self._repeat_count += 1
            return
        self._flush_repetition()
        self._repeat_record = record
        self._repeat_count = 1
        self._repeat_start = self._raw_line

    def _flush_progress(self) -> None:
        if self._progress_first is None or self._progress_last is None:
            return
        self._flush_repetition()
        self.line_clipped = self.line_clipped or self._progress_first.clipped
        self.line_clipped = self.line_clipped or self._progress_last.clipped
        first = self._progress_first.render()
        self._collector.add(f"{first}\n", failure_anchor=_is_failure_anchor(first))
        if self._progress_count > 2:
            final_update = self._progress_count - 1
            progress_marker = (
                "[progress updates 2-"
                f"{final_update} collapsed; raw updates 2-{final_update}]"
            )
            self._collector.add(f"{progress_marker}\n")
        if self._progress_count > 1:
            last = self._progress_last.render()
            self._collector.add(f"{last}\n", failure_anchor=_is_failure_anchor(last))
        self._progress_first = None
        self._progress_last = None
        self._progress_count = 0

    def _flush_repetition(self) -> None:
        if self._repeat_record is None:
            return
        text = self._repeat_record.render()
        self.line_clipped = self.line_clipped or self._repeat_record.clipped
        if self._repeat_count > 1:
            self.repetition_collapsed = True
            end = self._repeat_start + self._repeat_count - 1
            text += (
                f" [line repeated {self._repeat_count} times; raw lines "
                f"{self._repeat_start}-{end}]"
            )
        self._collector.add(f"{text}\n", failure_anchor=_is_failure_anchor(text))
        self._repeat_record = None
        self._repeat_count = 0


class _PrefixCollector:
    """Collect a UTF-8-safe prefix without exceeding any hard limit."""

    def __init__(self, limits: ProjectionLimits) -> None:
        self._limits = limits
        self.characters: list[str] = []
        self.byte_count = 0
        self.line_count = 0
        self._current_line_counted = False
        self.truncated = False

    def add(self, text: str, *, failure_anchor: bool = False) -> None:
        """Add display text; base prefix projection ignores failure anchors."""
        del failure_anchor
        if self.truncated:
            return
        for character in text:
            encoded_length = len(character.encode("utf-8"))
            next_bytes = self.byte_count + encoded_length
            next_lines = self.line_count
            next_current_counted = self._current_line_counted
            if character == "\n":
                if not next_current_counted:
                    next_lines += 1
                next_current_counted = False
            elif not next_current_counted:
                next_lines += 1
                next_current_counted = True

            if (
                next_bytes > self._limits.max_bytes
                or next_lines > self._limits.max_lines
                or _estimate_tokens(next_bytes) > self._limits.max_estimated_tokens
            ):
                self.truncated = True
                return

            self.characters.append(character)
            self.byte_count = next_bytes
            self.line_count = next_lines
            self._current_line_counted = next_current_counted

    def finish(self) -> tuple[str, str | None]:
        prefix = "".join(self.characters)
        if not self.truncated:
            return prefix, None

        for marker in (OMISSION_MARKER, "[omitted]", "[...]", "…"):
            candidate_prefix = prefix
            while True:
                separator = "\n" if candidate_prefix and not candidate_prefix.endswith("\n") else ""
                candidate = f"{candidate_prefix}{separator}{marker}"
                if _fits(candidate, self._limits):
                    return candidate, marker
                if not candidate_prefix:
                    break
                candidate_prefix = candidate_prefix[:-1]

        # A one- or two-byte budget cannot contain a descriptive marker.  A
        # visible full stop is still an explicit gap sentinel in the metadata.
        marker = "."
        return marker, marker

    def trim_to(self, limits: ProjectionLimits) -> None:
        """Retain only the prefix that fits tighter limits in-place."""
        byte_count = 0
        line_count = 0
        current_line_counted = False
        end = 0
        for end, character in enumerate(self.characters, start=1):
            encoded_length = len(character.encode("utf-8"))
            next_bytes = byte_count + encoded_length
            next_lines = line_count
            next_current_counted = current_line_counted
            if character == "\n":
                if not next_current_counted:
                    next_lines += 1
                next_current_counted = False
            elif not next_current_counted:
                next_lines += 1
                next_current_counted = True
            if (
                next_bytes > limits.max_bytes
                or next_lines > limits.max_lines
                or _estimate_tokens(next_bytes) > limits.max_estimated_tokens
            ):
                end -= 1
                break
            byte_count = next_bytes
            line_count = next_lines
            current_line_counted = next_current_counted
        else:
            end = len(self.characters)

        del self.characters[end:]
        self.byte_count = byte_count
        self.line_count = line_count
        self._current_line_counted = current_line_counted


class _BoundedRecordBuffer:
    """Store complete normalized records within independent hard limits."""

    def __init__(self, limits: ProjectionLimits, *, rolling: bool) -> None:
        self._limits = limits
        self._rolling = rolling
        self._records: list[tuple[str, int, int]] = []
        self._byte_count = 0
        self._line_count = 0

    def add(self, text: str) -> None:
        byte_count = len(text.encode("utf-8"))
        line_count = _line_count(text)
        if byte_count > self._limits.max_bytes or line_count > self._limits.max_lines:
            return
        if self._rolling:
            while self._records and (
                self._byte_count + byte_count > self._limits.max_bytes
                or self._line_count + line_count > self._limits.max_lines
            ):
                _, removed_bytes, removed_lines = self._records.pop(0)
                self._byte_count -= removed_bytes
                self._line_count -= removed_lines
        if (
            self._byte_count + byte_count > self._limits.max_bytes
            or self._line_count + line_count > self._limits.max_lines
        ):
            return
        self._records.append((text, byte_count, line_count))
        self._byte_count += byte_count
        self._line_count += line_count

    @property
    def text(self) -> str:
        return "".join(record[0] for record in self._records)


class _FailureCollector(_PrefixCollector):
    """Add bounded failure context and a tail after ordinary prefix truncation."""

    def __init__(self, limits: ProjectionLimits) -> None:
        super().__init__(limits)
        self._selection_active = False
        self._failure_found = False
        self._before: list[str] = []
        self._after_remaining = 0
        self._anchors: _BoundedRecordBuffer | None = None
        self._tail: _BoundedRecordBuffer | None = None

    def add(self, text: str, *, failure_anchor: bool = False) -> None:
        was_truncated = self.truncated
        super().add(text)
        if not was_truncated and self.truncated:
            self._activate_selection()
        if not self._selection_active:
            return

        assert self._anchors is not None
        assert self._tail is not None
        self._tail.add(text)
        if failure_anchor:
            if self._after_remaining == 0:
                for context in self._before:
                    self._anchors.add(context)
            self._anchors.add(text)
            self._failure_found = True
            self._after_remaining = _FAILURE_CONTEXT_AFTER
        elif self._after_remaining:
            self._anchors.add(text)
            self._after_remaining -= 1

        self._before.append(text)
        if len(self._before) > _FAILURE_CONTEXT_BEFORE:
            self._before.pop(0)

    def _activate_selection(self) -> None:
        marker_bytes = len(f"{OMISSION_MARKER}\n".encode()) * 2
        marker_lines = 2
        byte_budget = min(
            self._limits.max_bytes,
            self._limits.max_estimated_tokens * 4,
        ) - marker_bytes
        line_budget = self._limits.max_lines - marker_lines
        if byte_budget < 3 or line_budget < 3:
            return

        head_bytes = byte_budget // 4
        anchor_bytes = byte_budget // 2
        tail_bytes = byte_budget - head_bytes - anchor_bytes
        head_lines = line_budget // 4
        anchor_lines = line_budget // 2
        tail_lines = line_budget - head_lines - anchor_lines
        if min(head_bytes, anchor_bytes, tail_bytes, head_lines, anchor_lines, tail_lines) <= 0:
            return

        self.trim_to(
            ProjectionLimits(head_bytes, head_lines, max(1, head_bytes // 4))
        )
        self._anchors = _BoundedRecordBuffer(
            ProjectionLimits(anchor_bytes, anchor_lines, max(1, anchor_bytes // 4)),
            rolling=False,
        )
        self._tail = _BoundedRecordBuffer(
            ProjectionLimits(tail_bytes, tail_lines, max(1, tail_bytes // 4)),
            rolling=True,
        )
        self._selection_active = True

    def finish(self) -> tuple[str, str | None]:
        if not self._selection_active or not self._failure_found:
            return super().finish()

        assert self._anchors is not None
        assert self._tail is not None
        sections = ("".join(self.characters), self._anchors.text, self._tail.text)
        selected: list[str] = []
        for index, section in enumerate(sections):
            if section:
                selected.append(section if section.endswith("\n") else f"{section}\n")
            if index < len(sections) - 1:
                selected.append(f"{OMISSION_MARKER}\n")

        text = "".join(selected)
        if _fits(text, self._limits):
            return text, OMISSION_MARKER
        # The allocation above reserves both markers, but retain the ordinary
        # bounded fallback for unusual multi-line normalized records.
        fallback = _PrefixCollector(self._limits)
        fallback.add(text)
        return fallback.finish()


def _estimate_tokens(byte_count: int) -> int:
    """Estimate tokens using the policy's ``utf8-bytes-div-4-v1`` rule."""
    return (byte_count + 3) // 4


def _line_count(text: str) -> int:
    if not text:
        return 0
    count = 0
    current_counted = False
    for character in text:
        if character == "\n":
            if not current_counted:
                count += 1
            current_counted = False
        elif not current_counted:
            count += 1
            current_counted = True
    return count


def _fits(text: str, limits: ProjectionLimits) -> bool:
    byte_count = len(text.encode("utf-8"))
    return (
        byte_count <= limits.max_bytes
        and _line_count(text) <= limits.max_lines
        and _estimate_tokens(byte_count) <= limits.max_estimated_tokens
    )


def _coerce_values(values: Iterable[bytes | str]) -> tuple[bytes, ...]:
    return tuple(
        value.encode("utf-8") if isinstance(value, str) else bytes(value)
        for value in values
    )


def _coerce_rules(
    rules: Mapping[str, Iterable[bytes | str]],
) -> tuple[tuple[str, bytes], ...]:
    """Convert named exact-match rules without retaining names in output text."""
    converted: list[tuple[str, bytes]] = []
    for identifier in sorted(rules):
        values = rules[identifier]
        converted.extend((identifier, value) for value in _coerce_values(values))
    return tuple(converted)


def project_bytes(
    chunks: bytes | Iterable[bytes],
    *,
    exact_values: Iterable[bytes | str] = (),
    exact_secrets: Iterable[bytes | str] | None = None,
    exact_redaction_rules: Mapping[str, Iterable[bytes | str]] | None = None,
    replacement: bytes | str = b"[REDACTED]",
    limits: ProjectionLimits | None = None,
    max_bytes: int = 65_536,
    max_lines: int = 2_000,
    max_estimated_tokens: int = 16_000,
) -> ProjectionResult:
    """Project supplied byte chunks into deterministic, safe, bounded output.

    Exact values are redacted before decoding, so a value can span any input
    chunk boundary.  Invalid UTF-8 uses the standard replacement character and
    terminal/Unicode controls are rendered as visible ASCII escapes.
    """
    if limits is None:
        limits = ProjectionLimits(max_bytes, max_lines, max_estimated_tokens)
    elif (max_bytes, max_lines, max_estimated_tokens) != (65_536, 2_000, 16_000):
        raise ValueError("pass either limits or individual limit arguments, not both")

    values = tuple(exact_values)
    if exact_secrets is not None:
        if values:
            raise ValueError("pass either exact_values or exact_secrets, not both")
        values = tuple(exact_secrets)
    if exact_redaction_rules is not None and values:
        raise ValueError("pass exact_redaction_rules or exact values, not both")
    replacement_bytes = (
        replacement.encode("utf-8")
        if isinstance(replacement, str)
        else bytes(replacement)
    )
    if not replacement_bytes:
        raise ValueError("replacement must not be empty")

    rules = (
        _coerce_rules(exact_redaction_rules)
        if exact_redaction_rules is not None
        else tuple(("exact-value", value) for value in _coerce_values(values))
    )
    redactor = _ExactRedactor(rules, replacement_bytes)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    collector = _FailureCollector(limits)
    normalizer = _ProjectionNormalizer(collector, limits)

    supplied_chunks: Iterable[bytes] = (chunks,) if isinstance(chunks, bytes) else chunks
    for chunk in supplied_chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("projection chunks must be bytes")
        for offset in range(0, len(chunk), _PROCESSING_CHUNK_BYTES):
            redacted = redactor.feed(chunk[offset : offset + _PROCESSING_CHUNK_BYTES])
            normalizer.feed(decoder.decode(redacted, final=False))

    decoded = decoder.decode(redactor.feed(b"", final=True), final=True)
    normalizer.feed(decoded)
    normalizer.finish()
    collector.truncated = collector.truncated or normalizer.line_clipped

    text, gap_marker = collector.finish()
    output = text.encode("utf-8")
    return ProjectionResult(
        output=output,
        text=text,
        bytes=len(output),
        lines=_line_count(text),
        estimated_tokens=_estimate_tokens(len(output)),
        lossy=(
            redactor.redacted
            or normalizer.controls_changed
            or normalizer.repetition_collapsed
            or gap_marker is not None
            or "�" in text
        ),
        normalized=True,
        redacted=redactor.redacted,
        sha256=hashlib.sha256(output).hexdigest(),
        gap_marker=gap_marker,
        redaction_rules=redactor.rules,
    )


# A concise alias for callers that already know the input is a byte stream.
project = project_bytes
