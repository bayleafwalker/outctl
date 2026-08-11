from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from outctl.serialization import canonical_json_text, canonical_sha256

ROOT = Path(__file__).parents[1]
V2 = ROOT / "schemas" / "v2"
EXAMPLES = ROOT / "examples" / "v2"
CONFORMANCE = ROOT / "conformance" / "v2"


def _comparator() -> object:
    spec = importlib.util.spec_from_file_location(
        "outctl_w1_conformance_comparator", CONFORMANCE / "comparator.py"
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load W1 comparator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_COMPARATOR = _comparator()
ComparisonMismatch = _COMPARATOR.ComparisonMismatch  # type: ignore[attr-defined]
validate_matrix = _COMPARATOR.validate_matrix  # type: ignore[attr-defined]
validate_policy_binding = _COMPARATOR.validate_policy_binding  # type: ignore[attr-defined]


def _schema(name: str) -> dict[str, object]:
    return json.loads((V2 / name).read_text(encoding="utf-8"))


def _example(name: str) -> dict[str, object]:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", sorted(V2.glob("*.schema.json")))
def test_v2_schemas_are_valid_and_examples_validate(path: Path) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    examples = {
        "run-request.schema.json": ["run-request.trusted.json", "run-request.restricted.json"],
        "policy-snapshot.schema.json": ["policy-snapshot.json"],
        "run-result.schema.json": ["run-result.bypassed.json", "run-result.unsupported.json"],
        "engine-capabilities.schema.json": ["engine-capabilities.json"],
        "capture-manifest-delta.schema.json": ["capture-manifest-delta.json"],
    }
    for example in examples[path.name]:
        jsonschema.Draft202012Validator(schema).validate(_example(example))


def test_policy_snapshot_cannot_grant_execution() -> None:
    value = _example("policy-snapshot.json")
    value["execution_authority"]["can_authorize_execution"] = True  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(_schema("policy-snapshot.schema.json")).validate(value)


def _assert_invalid(schema_name: str, value: dict[str, object]) -> None:
    validator = jsonschema.Draft202012Validator(_schema(schema_name))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(value)


def test_requests_reject_cross_mode_trust_and_secret_states() -> None:
    base = _example("run-request.trusted.json")

    explicit_without_command = deepcopy(base)
    explicit_without_command["command"]["execution_mode"] = "explicit-shell"  # type: ignore[index]
    _assert_invalid("run-request.schema.json", explicit_without_command)

    direct_with_shell = deepcopy(base)
    direct_with_shell["command"]["shell_command"] = "printf unsafe"  # type: ignore[index]
    _assert_invalid("run-request.schema.json", direct_with_shell)

    restricted_unredacted = deepcopy(base)
    restricted_unredacted["sink"] = {  # type: ignore[assignment]
        "trust_domain": "restricted",
        "target": "handoff",
        "disclosure": "safe-unredacted",
    }
    _assert_invalid("run-request.schema.json", restricted_unredacted)

    metadata_sanitized = deepcopy(base)
    metadata_sanitized["sink"] = {  # type: ignore[assignment]
        "trust_domain": "metadata-only",
        "target": "handoff",
        "disclosure": "sanitized",
    }
    _assert_invalid("run-request.schema.json", metadata_sanitized)

    secret_values_in_channel = deepcopy(base)
    secret_values_in_channel["secret_channel"] = {  # type: ignore[assignment]
        "mode": "none",
        "refs": ["secret://must-not-be-present-in-none"],
    }
    _assert_invalid("run-request.schema.json", secret_values_in_channel)


def test_policy_snapshot_rejects_trust_capture_and_cache_contradictions() -> None:
    base = _example("policy-snapshot.json")

    uncommissioned_trusted = deepcopy(base)
    uncommissioned_trusted["session"]["commissioned"] = False  # type: ignore[index]
    _assert_invalid("policy-snapshot.schema.json", uncommissioned_trusted)

    ephemeral_required = deepcopy(base)
    ephemeral_required["capture"] = {  # type: ignore[assignment]
        "commitment": "memory-only",
        "durability": "none",
        "required": True,
    }
    _assert_invalid("policy-snapshot.schema.json", ephemeral_required)

    wrong_cache_owner = deepcopy(base)
    wrong_cache_owner["cache"]["owner"] = "runner"  # type: ignore[index]
    _assert_invalid("policy-snapshot.schema.json", wrong_cache_owner)

    restricted_unredacted = deepcopy(base)
    restricted_unredacted["sinks"][1]["disclosure"] = "safe-unredacted"  # type: ignore[index]
    _assert_invalid("policy-snapshot.schema.json", restricted_unredacted)


def test_results_reject_cross_outcome_status_states() -> None:
    bypass = _example("run-result.bypassed.json")

    unsupported_started = deepcopy(bypass)
    unsupported_started["outcome"] = "unsupported"
    _assert_invalid("run-result.schema.json", unsupported_started)

    bypass_with_capture = deepcopy(bypass)
    bypass_with_capture["capture"]["status"] = "complete"  # type: ignore[index]
    bypass_with_capture["capture"]["complete"] = True  # type: ignore[index]
    _assert_invalid("run-result.schema.json", bypass_with_capture)

    exit_and_signal = deepcopy(bypass)
    exit_and_signal["command"]["exit_code"] = 1  # type: ignore[index]
    exit_and_signal["command"]["signal"] = 9  # type: ignore[index]
    _assert_invalid("run-result.schema.json", exit_and_signal)

    wrong_wrapper_phase = _example("run-result.unsupported.json")
    wrong_wrapper_phase["wrapper_error"]["phase"] = "post-spawn"  # type: ignore[index]
    _assert_invalid("run-result.schema.json", wrong_wrapper_phase)


def test_snapshot_binding_is_exact_across_request_cache_and_result() -> None:
    snapshot = _example("policy-snapshot.json")
    request = _example("run-request.trusted.json")
    result = _example("run-result.bypassed.json")
    delta = _example("capture-manifest-delta.json")
    expected = {
        "snapshot_id": snapshot["snapshot_id"],
        "ref": snapshot["policy_ref"],
        "digest": snapshot["policy_digest"],
    }
    assert snapshot["cache"]["snapshot_id"] == expected["snapshot_id"]  # type: ignore[index]
    for document in (request, result, delta):
        validate_policy_binding(snapshot, document)

    for field in ("snapshot_id", "ref", "digest"):
        mismatched = deepcopy(delta)
        if field == "snapshot_id":
            mismatched["policy"][field] = "snapshot-2"  # type: ignore[index]
        elif field == "ref":
            mismatched["policy"][field] = "policy://other"  # type: ignore[index]
        else:
            mismatched["policy"][field] = "sha256:" + "f" * 64  # type: ignore[index]
        with pytest.raises(ComparisonMismatch, match="policy binding mismatch"):
            validate_policy_binding(snapshot, mismatched)

    bad_cache = deepcopy(snapshot)
    bad_cache["cache"]["snapshot_id"] = "snapshot-2"  # type: ignore[index]
    with pytest.raises(ComparisonMismatch, match="policy cache snapshot_id mismatch"):
        validate_policy_binding(bad_cache, request)


def test_capture_delta_freezes_v1_writer_stance() -> None:
    delta = _example("capture-manifest-delta.json")
    compatibility = delta["compatibility"]
    assert compatibility["v1_writer"] == "python-reference-only"  # type: ignore[index]
    assert compatibility["v1_manifest_byte_exact"] is False  # type: ignore[index]

    byte_exact_claim = deepcopy(delta)
    byte_exact_claim["compatibility"]["v1_manifest_byte_exact"] = True  # type: ignore[index]
    _assert_invalid("capture-manifest-delta.schema.json", byte_exact_claim)


def test_bypass_and_unsupported_are_explicit() -> None:
    bypass = _example("run-result.bypassed.json")
    unsupported = _example("run-result.unsupported.json")
    assert bypass["outcome"] == "bypassed"
    assert unsupported["outcome"] == "unsupported"
    assert unsupported["wrapper_error"]["phase"] == "pre-spawn"  # type: ignore[index]


def test_canonical_digest_vectors_are_engine_independent() -> None:
    vectors = json.loads((ROOT / "conformance/v2/digest-vectors.json").read_text(encoding="utf-8"))
    for vector in vectors["vectors"]:
        assert canonical_json_text(vector["value"]) == vector["canonical_json"]
        assert "sha256:" + canonical_sha256(vector["value"]) == vector["sha256"]


def test_raw_free_comparison_matrix_is_machine_checked() -> None:
    matrix = json.loads((CONFORMANCE / "matrix.json").read_text(encoding="utf-8"))
    reports = validate_matrix(matrix)
    assert {report.case_id for report in reports} == {
        "exact-direct-result",
        "semantic-with-declared-engine-differences",
        "negative-exact-stream-digest-mismatch",
        "negative-semantic-command-mismatch",
        "negative-undeclared-intentional-difference",
    }
    assert all(report.passed for report in reports if not report.case_id.startswith("negative-"))
    assert all(not report.passed for report in reports if report.case_id.startswith("negative-"))


def test_capture_delta_preserves_v1_compatibility_claim() -> None:
    delta = _example("capture-manifest-delta.json")
    assert delta["base_schema_version"] == "vuoro.outctl.capture/v1alpha1"
    assert delta["compatibility"]["v1_reader"] == "readable"  # type: ignore[index]
    assert delta["compatibility"]["v1_stream_bytes_preserved"] is True  # type: ignore[index]


def test_built_wheel_contains_exact_v2_contract_and_conformance_membership() -> None:
    wheels = sorted((ROOT / "dist").glob("outctl-*.whl"))
    assert wheels, "wheel is produced by the package gate before this test"
    with zipfile.ZipFile(wheels[-1]) as archive:
        names = set(archive.namelist())
    expected = {f"outctl/examples/v2/{path.name}" for path in sorted(EXAMPLES.glob("*.json"))}
    expected.update(
        {
            "outctl/conformance/v2/README.md",
            "outctl/conformance/v2/comparator.py",
            "outctl/conformance/v2/digest-vectors.json",
            "outctl/conformance/v2/matrix.json",
        }
    )
    actual = {
        name
        for name in names
        if name.startswith("outctl/examples/v2/") or name.startswith("outctl/conformance/v2/")
    }
    assert actual == expected
    assert {
        "outctl/schemas/v2/run-request.schema.json",
        "outctl/schemas/v2/capture-manifest-delta.schema.json",
    }.issubset(names)


def test_v2_examples_do_not_contain_raw_or_local_path_fields() -> None:
    forbidden = {
        "stdout",
        "stderr",
        "raw_output",
        "projection_body",
        "local_path",
        "spool_path",
        "secret_value",
        "secret_values",
        "secret_material",
    }

    def walk(value: object) -> None:
        if isinstance(value, dict):
            assert not forbidden.intersection(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for path in sorted(EXAMPLES.glob("*.json")):
        walk(json.loads(path.read_text(encoding="utf-8")))
