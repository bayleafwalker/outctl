from __future__ import annotations

import json
from pathlib import Path

import pytest

from outctl.cli import main
from outctl.control import (
    ClaimProvenance,
    CommissioningContext,
    compile_policy_source,
)

ROOT = Path(__file__).parents[1]


def _context_dict() -> dict[str, object]:
    return {
        "session_id": "session-1",
        "trust_domain": "trusted-local",
        "commissioned": True,
        "issued_at": "2026-08-12T08:00:00Z",
        "valid_for_ms": 3_600_000,
        "claims": [
            {
                "name": "trust_domain",
                "value": "trusted-local",
                "issuer": "host-policy",
                "evidence_ref": "audit://trust/1",
                "evidence_digest": "sha256:" + "a" * 64,
            },
            {
                "name": "commissioned",
                "value": True,
                "issuer": "host-policy",
                "evidence_ref": "audit://commission/1",
                "evidence_digest": "sha256:" + "b" * 64,
            },
        ],
    }


def test_checked_in_snapshot_is_exact_python_compiler_output() -> None:
    compiled = compile_policy_source(
        ROOT / "config",
        "w5-policy.example.yaml",
        CommissioningContext(
            session_id="session-1",
            trust_domain="trusted-local",
            commissioned=True,
            issued_at="2026-08-12T08:00:00Z",
            valid_for_ms=3_600_000,
            claims=(
                ClaimProvenance(
                    "trust_domain",
                    "trusted-local",
                    "host-policy",
                    "audit://trust/1",
                    "sha256:" + "a" * 64,
                ),
                ClaimProvenance(
                    "commissioned",
                    True,
                    "host-policy",
                    "audit://commission/1",
                    "sha256:" + "b" * 64,
                ),
            ),
        ),
    )
    checked_in = json.loads((ROOT / "examples/v2/policy-snapshot.json").read_text(encoding="utf-8"))
    assert compiled.snapshot.to_dict() == checked_in
    assert compiled.provenance.digest == (
        "sha256:5b78604473ec089f82490fa1074bf7de61a49be99c4306ebc63a6c1386da0e10"
    )


@pytest.mark.parametrize("operation", ["lint", "explain"])
def test_policy_cli_is_raw_free_and_root_confined(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], operation: str
) -> None:
    context = tmp_path / "context.json"
    context.write_text(json.dumps(_context_dict()), encoding="utf-8")
    code = main(
        [
            "policy",
            operation,
            "--policy-root",
            str(ROOT / "config"),
            "--context",
            str(context),
            "w5-policy.example.yaml",
        ]
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "can_authorize_execution" in output or '"valid":true' in output
    assert "value" not in output


def test_policy_cli_error_does_not_echo_unknown_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exact = "cli-must-not-echo-this-secret"
    context_value = _context_dict()
    context_value["secret_value"] = exact
    context = tmp_path / "context.json"
    context.write_text(json.dumps(context_value), encoding="utf-8")
    code = main(
        [
            "policy",
            "lint",
            "--policy-root",
            str(ROOT / "config"),
            "--context",
            str(context),
            "w5-policy.example.yaml",
        ]
    )
    output = capsys.readouterr().out
    assert code == 2
    assert exact not in output
