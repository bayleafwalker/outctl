from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest

from outctl.control import CapabilityNegotiationError, EngineCapabilities, negotiate_capabilities

ROOT = Path(__file__).parents[1]

pytestmark = pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required")


def test_native_capabilities_are_schema_valid_and_not_negotiable() -> None:
    completed = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--package",
            "outctl-cli",
            "--bin",
            "outctl-native",
            "--",
            "capabilities",
            "--json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(completed.stdout)
    schema = json.loads(
        (ROOT / "schemas/v2/engine-capabilities.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(document)

    assert document["contract_versions"] == {
        "run_request": [],
        "policy_snapshot": [],
        "run_result": [],
        "capture_manifest": [],
    }
    assert document["features"] == {
        "direct_argv": True,
        "explicit_shell": False,
        "stdin": False,
        "retrieval": False,
        "one_version_back_read": True,
    }

    capabilities = EngineCapabilities.from_dict(document)
    with pytest.raises(CapabilityNegotiationError, match="unsupported contracts"):
        negotiate_capabilities(capabilities)
