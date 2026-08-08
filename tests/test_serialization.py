from __future__ import annotations

import json

import pytest

from outctl.serialization import canonical_json_bytes, canonical_json_text, canonical_sha256


def test_canonical_json_is_deterministic() -> None:
    a = {"z": 1, "a": 2, "nested": {"b": 3, "a": 4}}
    b = {"a": 2, "z": 1, "nested": {"a": 4, "b": 3}}
    assert canonical_json_bytes(a) == canonical_json_bytes(b)


def test_canonical_json_has_no_whitespace() -> None:
    data = {"a": 1, "b": [2, 3]}
    text = canonical_json_text(data)
    assert " " not in text
    assert "\n" not in text
    assert text == '{"a":1,"b":[2,3]}'


def test_canonical_json_preserves_unicode_without_escapes() -> None:
    data = {"message": "héllo 世界"}
    text = canonical_json_text(data)
    assert "\\u" not in text
    assert text == '{"message":"héllo 世界"}'


def test_canonical_json_omits_none() -> None:
    data = {"a": 1, "b": None, "c": "x"}
    text = canonical_json_text(data)
    assert text == '{"a":1,"c":"x"}'


def test_canonical_sha256_matches_manual() -> None:
    data = {"a": 1, "b": 2}
    expected = __import__("hashlib").sha256(canonical_json_bytes(data)).hexdigest()
    assert canonical_sha256(data) == expected


@pytest.mark.parametrize(
    ("description", "data"),
    [
        ("empty object", {}),
        ("nested", {"x": {"y": {"z": [1, 2, 3]}}}),
        ("mixed", {"bool": True, "int": 42, "str": "s", "list": [None, 1, "a"]}),
    ],
)
def test_canonical_json_roundtrips(description: str, data: dict) -> None:
    text = canonical_json_text(data)
    parsed = json.loads(text)
    assert parsed == data


def test_equivalent_yaml_spellings_produce_same_digest() -> None:
    """Two dicts representing equivalent YAML policies digest identically."""
    spelling_one = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicy",
        "metadata": {"name": "example"},
        "spec": {
            "capture": {"required": False, "backend": "local"},
            "budget": {"maxEstimatedTokens": 100, "maxBytes": 1024},
        },
    }
    spelling_two = {
        "kind": "OutputPolicy",
        "apiVersion": "vuoro.outctl/v1alpha1",
        "metadata": {"name": "example"},
        "spec": {
            "budget": {"maxBytes": 1024, "maxEstimatedTokens": 100},
            "capture": {"backend": "local", "required": False},
        },
    }
    assert canonical_sha256(spelling_one) == canonical_sha256(spelling_two)
