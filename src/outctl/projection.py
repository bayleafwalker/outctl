"""Deterministic, bounded projection of captured byte streams.

This module operates on supplied bytes only.  It does not read captures or
rerun commands, and it keeps at most the configured projection budget in
memory.
"""

from __future__ import annotations

import codecs
import hashlib
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

OMISSION_MARKER = "[... output omitted ...]"


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

    @property
    def digest(self) -> str:
        """Return the algorithm-qualified projection digest."""
        return f"sha256:{self.sha256}"

    @property
    def omitted(self) -> bool:
        """Return whether a budget caused output omission."""
        return self.gap_marker is not None


class _ExactRedactor:
    """Streaming byte redactor with deterministic longest-match precedence."""

    def __init__(self, values: Iterable[bytes], replacement: bytes) -> None:
        unique = set(values)
        if any(not value for value in unique):
            raise ValueError("exact redaction values must not be empty")
        self._values = tuple(sorted(unique, key=lambda value: (-len(value), value)))
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
            else:
                output.append(data[cursor])
                cursor += 1

        self._pending.extend(data[cursor:])

        return bytes(output)


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


class _PrefixCollector:
    """Collect a UTF-8-safe prefix without exceeding any hard limit."""

    def __init__(self, limits: ProjectionLimits) -> None:
        self._limits = limits
        self.characters: list[str] = []
        self.byte_count = 0
        self.line_count = 0
        self._current_line_counted = False
        self.truncated = False

    def add(self, text: str) -> None:
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


def project_bytes(
    chunks: bytes | Iterable[bytes],
    *,
    exact_values: Iterable[bytes | str] = (),
    exact_secrets: Iterable[bytes | str] | None = None,
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

    if exact_secrets is not None:
        if tuple(exact_values):
            raise ValueError("pass either exact_values or exact_secrets, not both")
        exact_values = exact_secrets
    replacement_bytes = (
        replacement.encode("utf-8")
        if isinstance(replacement, str)
        else bytes(replacement)
    )
    if not replacement_bytes:
        raise ValueError("replacement must not be empty")

    redactor = _ExactRedactor(_coerce_values(exact_values), replacement_bytes)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    collector = _PrefixCollector(limits)
    controls_changed = False

    supplied_chunks: Iterable[bytes] = (chunks,) if isinstance(chunks, bytes) else chunks
    for chunk in supplied_chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("projection chunks must be bytes")
        decoded = decoder.decode(redactor.feed(chunk), final=False)
        neutralized, changed = _neutralize_controls(decoded)
        controls_changed = controls_changed or changed
        collector.add(neutralized)

    decoded = decoder.decode(redactor.feed(b"", final=True), final=True)
    neutralized, changed = _neutralize_controls(decoded)
    controls_changed = controls_changed or changed
    collector.add(neutralized)

    text, gap_marker = collector.finish()
    output = text.encode("utf-8")
    return ProjectionResult(
        output=output,
        text=text,
        bytes=len(output),
        lines=_line_count(text),
        estimated_tokens=_estimate_tokens(len(output)),
        lossy=redactor.redacted or controls_changed or gap_marker is not None or "�" in text,
        normalized=True,
        redacted=redactor.redacted,
        sha256=hashlib.sha256(output).hexdigest(),
        gap_marker=gap_marker,
    )


# A concise alias for callers that already know the input is a byte stream.
project = project_bytes
