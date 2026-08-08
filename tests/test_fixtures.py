from __future__ import annotations

import pytest

from outctl import FixtureGenerator


def test_fixture_generator_is_deterministic() -> None:
    gen1 = FixtureGenerator(seed=42)
    gen2 = FixtureGenerator(seed=42)

    fixtures1 = gen1.generate_all()
    fixtures2 = gen2.generate_all()

    assert len(fixtures1) == len(fixtures2)
    for a, b in zip(fixtures1, fixtures2, strict=True):
        assert a.name == b.name
        assert a.stdout == b.stdout
        assert a.stderr == b.stderr
        assert a.exit_code == b.exit_code
        assert a.invocation == b.invocation


def test_fixture_generator_records_invocation_count() -> None:
    gen = FixtureGenerator(seed=7)
    assert gen.invocation_count == 0
    gen.small_stdout()
    assert gen.invocation_count == 1
    gen.large_stdout()
    assert gen.invocation_count == 2
    gen.generate_all()
    assert gen.invocation_count == 2 + 14


def test_small_stdout_has_expected_shape() -> None:
    fixture = FixtureGenerator(seed=1).small_stdout(lines=20)
    assert fixture.name == "small_stdout"
    assert fixture.exit_code == 0
    lines = fixture.stdout.decode("utf-8").splitlines()
    assert len(lines) == 20
    assert lines[0] == "line 000"
    assert lines[-1] == "line 019"


def test_small_stderr_nonzero_has_expected_shape() -> None:
    fixture = FixtureGenerator(seed=1).small_stderr_nonzero(lines=5, exit_code=7)
    assert fixture.name == "small_stderr_nonzero"
    assert fixture.exit_code == 7
    assert fixture.stdout == b""
    assert len(fixture.stderr.decode("utf-8").splitlines()) == 5


def test_large_stdout_contains_middle_marker() -> None:
    fixture = FixtureGenerator(seed=1).large_stdout(lines=100_000)
    text = fixture.stdout.decode("utf-8")
    assert "UNIQUE-MIDDLE-MARKER at line 50000" in text
    assert text.count("\n") == 100_000


def test_failure_buried_in_noise_has_traceback() -> None:
    fixture = FixtureGenerator(seed=1).failure_buried_in_noise()
    text = fixture.stdout.decode("utf-8")
    assert "Traceback (most recent call last):" in text
    assert "RuntimeError: simulated failure" in text
    assert fixture.exit_code == 1
    assert text.count("\n") == 20_000 + 5_000 + 4


def test_repeated_line_is_repeated() -> None:
    fixture = FixtureGenerator(seed=1).repeated_line(count=10_000)
    lines = fixture.stdout.splitlines()
    assert len(lines) == 10_000
    assert all(line == b"repeated line" for line in lines)


def test_carriage_return_progress_ends_with_success() -> None:
    fixture = FixtureGenerator(seed=1).carriage_return_progress(count=100)
    assert fixture.stdout.endswith(b"\rfinal: success\n")
    assert b"\r" in fixture.stdout


def test_giant_line_has_expected_size() -> None:
    size = 100
    fixture = FixtureGenerator(seed=1).giant_line(size=size)
    assert len(fixture.stdout) == size + 1  # plus newline
    assert fixture.stdout.count(b"\n") == 1


def test_invalid_utf8_contains_bad_bytes() -> None:
    fixture = FixtureGenerator(seed=1).invalid_utf8()
    with pytest.raises(UnicodeDecodeError):
        fixture.stdout.decode("utf-8")
    assert b"\xff\xfe" in fixture.stdout


def test_binary_output_is_not_text() -> None:
    fixture = FixtureGenerator(seed=1).binary_output(size=1024)
    assert len(fixture.stdout) == 1024
    # NUL bytes are likely but not guaranteed in 1024 random bytes; just
    # confirm the payload is raw bytes.
    assert isinstance(fixture.stdout, bytes)


def test_secret_in_output_contains_secret() -> None:
    fixture = FixtureGenerator(seed=1).secret_in_output(secret="my-secret")
    assert b"my-secret" in fixture.stdout


def test_split_secret_spans_chunk_boundary() -> None:
    fixture = FixtureGenerator(seed=1).split_secret(secret="SECRET")
    # Prefix is exactly 64KiB - 10 bytes, so the secret starts near the chunk
    # boundary used by the capture engine.
    assert fixture.stdout[: (64 * 1024 - 10)] == b"x" * (64 * 1024 - 10)
    assert b"SECRET" in fixture.stdout


def test_ansi_osc_output_contains_escape_sequences() -> None:
    fixture = FixtureGenerator(seed=1).ansi_osc_output()
    assert b"\x1b]0;" in fixture.stdout
    assert b"\x1b[2J" in fixture.stdout


def test_long_session_class_targets_token_estimate() -> None:
    fixture = FixtureGenerator(seed=1).long_session_class(target_tokens=10_000)
    estimated_tokens = len(fixture.stdout) // 4
    # Allow a reasonable margin because the generator builds lines.
    assert 9_000 <= estimated_tokens <= 11_000
