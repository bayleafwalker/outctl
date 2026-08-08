from __future__ import annotations

import hashlib

from outctl.projection import OMISSION_MARKER, ProjectionLimits, project_bytes


def test_projection_is_deterministic_and_chunk_independent() -> None:
    whole = project_bytes(b"alpha\nbeta\n")
    chunked = project_bytes([b"al", b"pha\nb", b"eta\n"])
    assert whole == chunked
    assert whole.sha256 == hashlib.sha256(whole.output).hexdigest()
    assert whole.digest == f"sha256:{whole.sha256}"


def test_exact_redaction_crosses_input_chunk_boundaries() -> None:
    result = project_bytes(
        [b"token=sec", b"ret-value done\n"],
        exact_values=[b"secret-value"],
    )
    assert result.text == "token=[REDACTED] done\n"
    assert result.redacted is True
    assert b"secret-value" not in result.output


def test_ansi_and_controls_are_neutralized() -> None:
    result = project_bytes([b"safe\x1b]0;title\x07\x1b[2J\x00\r\tend\n"])
    assert "\x1b" not in result.text
    assert "\x00" not in result.text
    assert "\\x1b]0;title\\x07\\x1b[2J\\x00\\r\\tend" in result.text
    assert result.lossy is True


def test_byte_cap_includes_an_explicit_gap_marker() -> None:
    result = project_bytes(b"x" * 1_000, max_bytes=48)
    assert result.bytes <= 48
    assert result.gap_marker == OMISSION_MARKER
    assert result.text.endswith(OMISSION_MARKER)
    assert result.omitted is True


def test_line_and_token_caps_are_hard() -> None:
    line_limited = project_bytes(b"one\ntwo\nthree\n", max_lines=2)
    token_limited = project_bytes(b"abcdefghijklmnopqrstuvwxyz", max_estimated_tokens=4)
    assert line_limited.lines <= 2
    assert line_limited.gap_marker is not None
    assert token_limited.estimated_tokens <= 4
    assert token_limited.gap_marker is not None


def test_invalid_utf8_uses_replacement_decoding() -> None:
    result = project_bytes([b"valid ", b"\xf0\x28", b"\x8c\x28 end"])
    assert "�" in result.text
    assert result.output.decode("utf-8") == result.text
    assert result.lossy is True


def test_arbitrary_binary_output_is_safe_utf8() -> None:
    result = project_bytes(bytes(range(256)), max_bytes=2_048)
    assert result.output.decode("utf-8") == result.text
    assert "\x00" not in result.text
    assert "\x1b" not in result.text
    assert "\\x00" in result.text
    assert "\\x1b" in result.text


def test_limits_object_enforces_all_caps() -> None:
    result = project_bytes(
        b"0123456789\n" * 20,
        limits=ProjectionLimits(max_bytes=64, max_lines=3, max_estimated_tokens=16),
    )
    assert result.bytes <= 64
    assert result.lines <= 3
    assert result.estimated_tokens <= 16
    assert result.gap_marker is not None
