"""Shared contract validation and one-version-back normalization."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

_DEVELOPMENT_SCHEMA_ROOT = Path(__file__).parents[2] / "schemas"
_SCHEMAS = frozenset(
    {
        "cross-harness-conformance",
        "enablement-evidence",
        "evidence-reference",
        "expected-facts",
        "logical-command-request",
        "runner-command-result",
        "scenario-manifest",
        "shadow-observation",
        "study-analysis",
        "study-protocol",
        "ux-evidence",
    }
)
_RAW_KEY = re.compile(
    r"^(stdout|stderr|raw_output|projection_body|events_jsonl|tool_body|transcript|credential|secret)$",
    re.IGNORECASE,
)
_PATH_KEY = re.compile(r"(spool|local)_?path", re.IGNORECASE)


class ContractValidationError(ValueError):
    """Raised for schema-invalid or semantically unsafe contract material."""


def _plain(value: object) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_plain(item) for item in value]
    return value


def _deny_unsafe(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ContractValidationError(f"contract key is not a string at {path}")
            if _RAW_KEY.fullmatch(key):
                raise ContractValidationError(
                    f"raw or sensitive body field is forbidden: {path}.{key}"
                )
            if _PATH_KEY.search(key):
                raise ContractValidationError(f"bare local/spool path is forbidden: {path}.{key}")
            _deny_unsafe(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _deny_unsafe(child, f"{path}[{index}]")


def _load_schema(name: str) -> dict[str, Any]:
    if name not in _SCHEMAS:
        raise ContractValidationError(f"unknown outctl contract schema: {name}")
    filename = f"{name}.schema.json"
    packaged = files("outctl").joinpath("schemas", filename)
    text = (
        packaged.read_text(encoding="utf-8")
        if packaged.is_file()
        else (_DEVELOPMENT_SCHEMA_ROOT / filename).read_text(encoding="utf-8")
    )
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ContractValidationError(f"schema {name} root is not an object")
    return value


def _validate_evidence_links(value: Mapping[str, Any]) -> None:
    evidence = value.get("evidence")
    if not isinstance(evidence, list):
        return
    identifiers: set[str] = set()
    for record in evidence:
        if not isinstance(record, Mapping):
            continue
        identifier = record.get("evidence_id")
        if not isinstance(identifier, str) or identifier in identifiers:
            raise ContractValidationError("enablement evidence IDs must be unique")
        identifiers.add(identifier)
        locator, digest = record.get("locator"), record.get("digest")
        if (
            isinstance(locator, str)
            and locator.startswith("artifact:sha256:")
            and digest != "sha256:" + locator.removeprefix("artifact:sha256:")
        ):
            raise ContractValidationError("artifact locator and digest do not bind same bytes")
    for section_name, section in value.items():
        if section_name in {"evidence", "authorization"} or not isinstance(section, Mapping):
            continue
        references = section.get("evidence_ids")
        if isinstance(references, list):
            missing = sorted(set(references) - identifiers)
            if missing:
                raise ContractValidationError(
                    f"{section_name} references missing evidence IDs: {missing}"
                )


def _canonical_digest(value: Mapping[str, Any], *, omit: str | None = None) -> str:
    body = {key: item for key, item in value.items() if key != omit}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _validate_semantics(name: str, value: Mapping[str, Any]) -> None:
    if name == "study-protocol":
        if value.get("protocol_digest") != _canonical_digest(value, omit="protocol_digest"):
            raise ContractValidationError("study protocol digest does not bind canonical bytes")
    elif name == "study-analysis":
        pairs = value.get("pairs")
        summary = value.get("paired_summary")
        if isinstance(pairs, list) and isinstance(summary, Mapping):
            valid = [
                pair
                for pair in pairs
                if isinstance(pair, Mapping) and pair.get("protocol_valid") is True
            ]
            if summary.get("protocol_valid_pairs") != len(valid):
                raise ContractValidationError("study protocol-valid pair count does not reconcile")
            additional = sum(
                pair.get("critical_miss_a") is True and pair.get("critical_miss_b") is False
                for pair in valid
            )
            if summary.get("additional_critical_misses") != additional:
                raise ContractValidationError("study critical-miss summary does not reconcile")
    elif name == "shadow-observation":
        equivalence = value.get("equivalence")
        if isinstance(equivalence, Mapping):
            components = (
                "exit_match",
                "signal_match",
                "stdout_digest_match",
                "stderr_digest_match",
                "cwd_match",
            )
            if equivalence.get("semantically_equivalent") is not all(
                equivalence.get(key) is True for key in components
            ):
                raise ContractValidationError("shadow equivalence contradicts component checks")
        overhead = value.get("overhead")
        if isinstance(overhead, Mapping):
            direct_ms = overhead.get("direct_median_ms")
            shadow_ms = overhead.get("shadow_median_ms")
            if isinstance(direct_ms, int) and isinstance(shadow_ms, int):
                delta_ms = shadow_ms - direct_ms
                if overhead.get("wall_time_delta_ms") != delta_ms:
                    raise ContractValidationError("shadow overhead delta does not match medians")
                accepted = (
                    delta_ms <= 100
                    if direct_ms < 1_000
                    else delta_ms * 1_000_000 < direct_ms * 50_000
                )
                if overhead.get("accepted") is not accepted:
                    raise ContractValidationError(
                        "shadow overhead acceptance contradicts paired-median-v1"
                    )
    elif name == "ux-evidence":
        retrievals = value.get("retrievals")
        contributed = value.get("retrievals_contributing_to_findings")
        if (
            isinstance(retrievals, int)
            and isinstance(contributed, int)
            and contributed > retrievals
        ):
            raise ContractValidationError("contributing retrievals exceed total retrievals")
    elif name == "cross-harness-conformance":
        fixtures = value.get("fixture_results")
        fixture_passed = isinstance(fixtures, list) and all(
            isinstance(fixture, Mapping)
            and all(
                fixture.get(key) is True
                for key in (
                    "bypass_equivalent",
                    "shadow_equivalent",
                    "enforce_envelope_equivalent",
                    "retrieval_equivalent",
                )
            )
            for fixture in fixtures
        )
        expected = (
            fixture_passed
            and value.get("alternate_executor_constrained") is True
            and value.get("one_version_back_readable") is True
        )
        if value.get("conformant") is not expected:
            raise ContractValidationError("conformance verdict contradicts fixture gates")
    elif name == "expected-facts":
        facts = value.get("facts")
        if isinstance(facts, list):
            identifiers = [fact.get("fact_id") for fact in facts if isinstance(fact, Mapping)]
            if len(identifiers) != len(set(identifiers)):
                raise ContractValidationError("expected fact IDs must be unique")
            if any(
                isinstance(fact, Mapping)
                and fact.get("critical") is True
                and fact.get("severity") not in {"critical", "high"}
                for fact in facts
            ):
                raise ContractValidationError(
                    "critical expected facts require high/critical severity"
                )
    elif name == "evidence-reference":
        start, end = value.get("start"), value.get("end")
        if isinstance(start, int) and isinstance(end, int) and end < start:
            raise ContractValidationError("evidence reference end precedes start")


def validate_contract(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one current contract and return a detached plain mapping."""
    plain = _plain(value)
    assert isinstance(plain, dict)
    _deny_unsafe(plain)
    validator = Draft202012Validator(_load_schema(name), format_checker=None)
    errors = sorted(validator.iter_errors(plain), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        location = "/".join(str(item) for item in error.absolute_path) or "<root>"
        raise ContractValidationError(f"{name} invalid at {location}: {error.message}")
    if name == "enablement-evidence":
        _validate_evidence_links(plain)
    _validate_semantics(name, plain)
    return plain


def normalize_enablement_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the previous unversioned packet shape as current v1.

    Legacy booleans remain evidence of local planning state only. The adapter
    adds explicit provenance and empty evidence references; it never upgrades
    a missing authorization or external gate into success.
    """
    if value.get("schema_version") == "vuoro.outctl.enablement-evidence/v1":
        return validate_contract("enablement-evidence", value)
    legacy = deepcopy(dict(value))
    zero = "0" * 40
    result: dict[str, Any] = {
        "schema_version": "vuoro.outctl.enablement-evidence/v1",
        "packet_id": "legacy-unversioned",
        "repository_commit": zero,
        "environment_id": "legacy-unknown",
        "authorization": {"class": "offline-local", "reference": None},
        "generated_at": "1970-01-01T00:00:00Z",
        "evidence": [],
    }

    def section(name: str) -> dict[str, Any]:
        current = legacy.get(name)
        return dict(current) if isinstance(current, Mapping) else {}

    result["foundation"] = {
        **{key: section("foundation").get(key) is True for key in (
            "schemas_valid", "policy_digest_stable", "full_repository_gate"
        )},
        "evidence_ids": [],
    }
    result["mechanism"] = {
        **{key: section("mechanism").get(key) is True for key in (
            "passed", "process_semantics_passed", "security_passed"
        )},
        "negative_tests_passed": section("mechanism").get("security_passed") is True,
        "evidence_ids": [],
    }
    identity = section("identity_boundary")
    pairs_value = identity.get("paired_receipts")
    pairs: list[Any] = pairs_value if isinstance(pairs_value, list) else []
    result["identity_boundary"] = {
        "direct_argv": identity.get("direct_argv") is True,
        "identity_source": identity.get("identity_source")
        if identity.get("identity_source") == "runner_injected"
        else "unavailable",
        "paired_receipts": [
            {"logical_command_id": f"legacy-{index}", "a": pair["a"], "b": pair["b"]}
            for index, pair in enumerate(pairs)
            if isinstance(pair, Mapping)
            and isinstance(pair.get("a"), str)
            and isinstance(pair.get("b"), str)
        ],
        "read_only_rbac": identity.get("read_only_rbac") is True,
        "negative_rbac_tests": False,
        "evidence_ids": [],
    }
    shadow = section("shadow")
    result["shadow"] = {
        **{key: shadow.get(key) is True for key in (
            "semantic_equivalence", "no_deadlocks", "recovery_verified", "overhead_acceptable"
        )},
        "rollback_verified": False,
        "evidence_ids": [],
    }
    study = section("controlled_study")
    reduction = study.get("median_command_output_reduction_pct")
    result["controlled_study"] = {
        "protocol_digest": None,
        "dataset_class": "unavailable",
        "frozen_protocol": study.get("frozen_protocol") is True,
        "protocol_valid_pairs": int(study.get("protocol_valid_pairs", 0)),
        "quality_noninferior": study.get("quality_noninferior") is True,
        "zero_additional_critical_misses": study.get("zero_additional_critical_misses") is True,
        "median_command_output_reduction_ppm": int(float(reduction) * 10_000)
        if isinstance(reduction, (int, float)) and not isinstance(reduction, bool)
        else None,
        "evidence_ids": [],
    }
    specifications = {
        "ux_pilot": ("multi_turn", "quality_preserved", "retrieval_contributed", "raw_free_report"),
        "selected_enforcement": (
            "approved_command_classes",
            "rollback_verified",
            "redaction_verified",
            "bypass_pressure_acceptable",
        ),
        "authority_integration": ("action_receipts", "audit_verification", "policy_promoted"),
        "hybrid": ("replica_classes_preserved", "cross_host_verified", "local_break_glass"),
    }
    for name, keys in specifications.items():
        old = section(name)
        result[name] = {**{key: old.get(key) is True for key in keys}, "evidence_ids": []}
    second = section("second_harness")
    result["second_harness"] = {
        "harness_id": None,
        "conformant": second.get("conformant") is True,
        "evidence_ids": [],
    }
    return validate_contract("enablement-evidence", result)
