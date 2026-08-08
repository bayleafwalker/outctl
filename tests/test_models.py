from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

import outctl.models as models
from outctl import (
    AuditEvent,
    CaptureManifest,
    CommandResultEnvelope,
    OutputPolicy,
    OutputPolicySet,
)

ROOT = Path(__file__).parents[1]


@pytest.fixture
def output_policy_schema() -> dict:
    return json.loads((ROOT / "schemas/output-policy.schema.json").read_text())


@pytest.fixture
def output_policy_set_schema() -> dict:
    return json.loads((ROOT / "schemas/output-policy-set.schema.json").read_text())


@pytest.fixture
def command_result_schema() -> dict:
    return json.loads((ROOT / "schemas/command-result-envelope.schema.json").read_text())


@pytest.fixture
def capture_manifest_schema() -> dict:
    return json.loads((ROOT / "schemas/capture-manifest.schema.json").read_text())


@pytest.fixture
def audit_event_schema() -> dict:
    return json.loads((ROOT / "schemas/audit-event.schema.json").read_text())


def test_output_policy_model_roundtrips(output_policy_schema: dict) -> None:
    data = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicy",
        "metadata": {"name": "test-policy"},
        "spec": {
            "capture": {
                "required": False,
                "backend": "local",
                "maxBytes": 1024,
                "onFailure": "warn",
                "onQuotaExceeded": "continue-truncated",
            },
            "budget": {
                "maxEstimatedTokens": 100,
                "maxBytes": 1024,
                "maxLines": 100,
                "estimator": "utf8-bytes-div-4-v1",
            },
            "projection": {"mode": "auto"},
            "redaction": {
                "beforeModel": True,
                "beforeLocalRaw": False,
                "beforeReplica": True,
            },
        },
    }
    policy = OutputPolicy.from_dict(data)
    assert policy.metadata.name == "test-policy"
    assert policy.spec.capture.backend == "local"
    roundtrip = policy.to_dict()
    jsonschema.Draft202012Validator(output_policy_schema).validate(roundtrip)


def test_output_policy_rejects_unknown_budget_field(output_policy_schema: dict) -> None:
    data = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicy",
        "metadata": {"name": "bad-policy"},
        "spec": {
            "capture": {
                "required": False,
                "backend": "local",
                "maxBytes": 1024,
                "onFailure": "warn",
                "onQuotaExceeded": "continue-truncated",
            },
            "budget": {
                "maxEstimatedTokens": 100,
                "maxBytes": 1024,
                "maxLines": 100,
                "estimator": "utf8-bytes-div-4-v1",
                "extraField": 1,
            },
            "projection": {"mode": "auto"},
            "redaction": {
                "beforeModel": True,
                "beforeLocalRaw": False,
                "beforeReplica": True,
            },
        },
    }
    with pytest.raises(ValueError):
        OutputPolicy.from_dict(data)


def test_output_policy_set_model_roundtrips(output_policy_set_schema: dict) -> None:
    data = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicySet",
        "metadata": {"name": "test-set"},
        "spec": {
            "defaults": {"policy": "default"},
            "policies": {
                "default": {
                    "capture": {"required": False},
                }
            },
            "profiles": [{"name": "tests", "policy": "default"}],
        },
    }
    policy_set = OutputPolicySet.from_dict(data)
    assert policy_set.spec.defaults.policy == "default"
    roundtrip = policy_set.to_dict()
    jsonschema.Draft202012Validator(output_policy_set_schema).validate(roundtrip)


def test_command_result_example_roundtrips(command_result_schema: dict) -> None:
    text = (ROOT / "examples/command-result-envelope.json").read_text()
    data = json.loads(text)
    envelope = CommandResultEnvelope.from_dict(data)
    assert envelope.schema_version == "vuoro.outctl.result/v1alpha1"
    roundtrip = envelope.to_dict()
    jsonschema.Draft202012Validator(command_result_schema).validate(roundtrip)
    assert roundtrip["capture_ref"] == data["capture_ref"]


def test_capture_manifest_model_roundtrips(capture_manifest_schema: dict) -> None:
    data = {
        "schema_version": "vuoro.outctl.capture/v1alpha1",
        "capture_id": "01K1TEST",
        "created_at": "2026-08-03T18:00:00Z",
        "source": {"host_id": "devbox", "workspace_id": "ws", "cwd": "/tmp"},
        "bindings": {},
        "policy": {"name": "interactive-default-v1", "digest": "sha256:" + "0" * 64},
        "command": {
            "argv_display": ["echo", "hi"],
            "shell": False,
            "started": True,
            "exit_code": 0,
            "signal": None,
            "timed_out": False,
            "cancelled": False,
        },
        "capture": {
            "status": "COMPLETE",
            "required": False,
            "max_bytes": 1024,
            "truncated": False,
        },
        "streams": {
            "stdout": {"path": "stdout.raw", "bytes": 3, "sha256": "a" * 64, "complete": True},
            "stderr": {"path": "stderr.raw", "bytes": 0, "sha256": None, "complete": True},
        },
        "event_index": {"path": "events.ndjson", "bytes": 0, "sha256": "b" * 64, "events": []},
    }
    manifest = CaptureManifest.from_dict(data)
    assert manifest.capture_id == "01K1TEST"
    roundtrip = manifest.to_dict()
    jsonschema.Draft202012Validator(capture_manifest_schema).validate(roundtrip)


def test_audit_event_model_roundtrips(audit_event_schema: dict) -> None:
    data = {
        "schema_version": "vuoro.outctl.audit-event/v1alpha1",
        "event_type": "command.capture.completed",
        "occurred_at": "2026-08-03T18:00:00Z",
        "capture_ref": "outctl://capture/01K1TEST/manifest/sha256:" + "0" * 64,
        "capture_manifest_sha256": "0" * 64,
        "bindings": {},
        "actor": {"host_id": "devbox"},
    }
    event = AuditEvent.from_dict(data)
    assert event.event_type == "command.capture.completed"
    roundtrip = event.to_dict()
    jsonschema.Draft202012Validator(audit_event_schema).validate(roundtrip)


def test_all_models_are_importable() -> None:
    # Ensures the public surface declared in __init__.py stays consistent.
    assert models.OutputPolicy is OutputPolicy
    assert models.OutputPolicySet is OutputPolicySet
    assert models.CommandResultEnvelope is CommandResultEnvelope
    assert models.CaptureManifest is CaptureManifest
    assert models.AuditEvent is AuditEvent
