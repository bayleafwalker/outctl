from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from outctl import __version__
from outctl.cli import main

ROOT = Path(__file__).parents[1]


def test_version_and_cli_scaffold() -> None:
    assert __version__ == "0.1.0.dev0"
    assert main([]) == 0


def test_result_example_matches_schema() -> None:
    schema = json.loads((ROOT / "schemas/command-result-envelope.schema.json").read_text())
    example = json.loads((ROOT / "examples/command-result-envelope.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(example)


def test_all_checked_in_schemas_are_valid_draft_2020_12() -> None:
    for path in sorted((ROOT / "schemas").glob("*.schema.json")):
        schema = json.loads(path.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
