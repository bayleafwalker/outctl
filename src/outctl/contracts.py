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
        "approved-command-policy",
        "cross-harness-conformance",
        "enablement-evidence",
        "enforcement-observation",
        "evidence-reference",
        "expected-facts",
        "logical-command-request",
        "runner-command-result",
        "arm-matrix",
        "scenario-package",
        "scenario-suite",
        "scenario-manifest",
        "shadow-observation",
        "study-analysis",
        "study-analysis-v2",
        "study-protocol",
        "study-suite",
        "ux-evidence",
    }
)
MAX_PROTOCOL_CANONICAL_BYTES = 64 * 1024
_RAW_KEY = re.compile(
    r"^(stdout|stderr|raw_output|projection_body|events_jsonl|tool_body|transcript|credential|secret)$",
    re.IGNORECASE,
)
_PATH_KEY = re.compile(r"(spool|local)_?path", re.IGNORECASE)


class ContractValidationError(ValueError):
    """Raised for schema-invalid or semantically unsafe contract material."""


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractValidationError(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractValidationError(f"{label} root must be an object")
    return value


def _repository_head(root: Path) -> str:
    dotgit = root / ".git"
    git_dir = dotgit
    if dotgit.is_file():
        marker = dotgit.read_text(encoding="utf-8").strip()
        if not marker.startswith("gitdir: "):
            raise ContractValidationError("repository .git indirection is invalid")
        git_dir = (root / marker.removeprefix("gitdir: ")).resolve()
    head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
    if re.fullmatch(r"[a-f0-9]{40,64}", head):
        return head
    if not head.startswith("ref: "):
        raise ContractValidationError("repository HEAD is not a commit or ref")
    reference = head.removeprefix("ref: ")
    candidates = [git_dir / reference]
    common_file = git_dir / "commondir"
    common = git_dir
    if common_file.is_file():
        common = (git_dir / common_file.read_text(encoding="utf-8").strip()).resolve()
        candidates.append(common / reference)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="ascii").strip()
    packed = common / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="ascii").splitlines():
            if line and not line.startswith(("#", "^")):
                commit, name = line.split(" ", 1)
                if name == reference:
                    return commit
    raise ContractValidationError(f"repository HEAD ref cannot be resolved: {reference}")


def _bound_repository_file(root: Path, binding: Mapping[str, Any], label: str) -> Path:
    raw = binding.get("path")
    if not isinstance(raw, str):
        raise ContractValidationError(f"{label} path is missing")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] == ("examples",):
        raise ContractValidationError(
            f"{label} path must be repository-relative, non-example, and traversal-free"
        )
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ContractValidationError(f"{label} path is outside the repository or missing")
    observed = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != binding.get("sha256"):
        raise ContractValidationError(f"{label} digest mismatch")
    return path


def _repository_file(root: Path, raw: object, label: str) -> Path:
    return _bound_repository_file(
        root,
        {
            "path": raw,
            "sha256": "sha256:" + hashlib.sha256((root / str(raw)).read_bytes()).hexdigest()
            if isinstance(raw, str)
            and not Path(raw).is_absolute()
            and ".." not in Path(raw).parts
            and (root / raw).is_file()
            else None,
        },
        label,
    )


def validate_controlled_study_launch(
    repository_root: Path,
    protocol_path: Path,
    scenario_id: str,
    *,
    mutation_authorized: bool = False,
) -> dict[str, Any]:
    """Fail closed on all frozen bindings before a controlled model launch."""
    root = repository_root.resolve()
    protocol = validate_contract(
        "study-protocol", _read_json_object(protocol_path, "study protocol")
    )
    if protocol.get("schema_version") != "vuoro.outctl.study-protocol/v2":
        raise ContractValidationError("controlled launch requires study-protocol/v2")
    if protocol.get("repository_commit") != _repository_head(root):
        raise ContractValidationError("study protocol repository commit does not match HEAD")
    suite_path = _repository_file(root, protocol.get("study_suite_path"), "study suite")
    suite = validate_contract("study-suite", _read_json_object(suite_path, "study suite"))
    if suite.get("suite_digest") != protocol.get("study_suite_digest"):
        raise ContractValidationError("protocol and suite canonical digests do not match")
    selected = [item for item in suite["scenarios"] if item.get("scenario_id") == scenario_id]
    if len(selected) != 1:
        raise ContractValidationError(f"scenario ID is not bound exactly once: {scenario_id}")
    binding = selected[0]
    manifest_path = _bound_repository_file(root, binding["manifest"], "scenario manifest")
    facts_path = _bound_repository_file(root, binding["expected_facts"], "expected facts")
    manifest = validate_contract(
        "scenario-manifest", _read_json_object(manifest_path, "scenario manifest")
    )
    facts = validate_contract("expected-facts", _read_json_object(facts_path, "expected facts"))
    if manifest.get("scenario_id") != scenario_id or facts.get("scenario_id") != scenario_id:
        raise ContractValidationError("scenario manifest/expected facts cross-binding mismatch")
    if manifest.get("scenario_class") != binding.get("scenario_class"):
        raise ContractValidationError("scenario class contradicts suite binding")
    fixture = str(manifest.get("fixture_digest", "")).removeprefix("sha256:")
    if not fixture or len(set(fixture)) == 1:
        raise ContractValidationError("scenario fixture digest is a placeholder")
    if manifest.get("expected_facts_digest") != binding["expected_facts"]["sha256"]:
        raise ContractValidationError("scenario manifest does not bind expected-facts bytes")
    if manifest.get("replayable") is not True:
        raise ContractValidationError("controlled scenario must be replayable")
    if manifest.get("mutation_authority_required") is True and not mutation_authorized:
        raise ContractValidationError("scenario requires mutation authority not granted to launch")
    return {"protocol": protocol, "suite": suite, "manifest": manifest, "expected_facts": facts}


def validate_scenario_launch(
    repository_root: Path,
    protocol_path: Path,
    scenario_id: str,
    *,
    mutation_authorized: bool = False,
) -> dict[str, Any]:
    """Resolve one provider-neutral v3 scenario without starting a runner.

    v1/v2 controlled-study documents remain readable by the historical
    acceptance launcher.  This resolver is intentionally v3-only: old
    artifacts are recorded results, not inputs that are silently upgraded to a
    new study compiler.
    """
    root = repository_root.resolve()
    protocol = validate_contract(
        "study-protocol", _read_json_object(protocol_path, "study protocol")
    )
    if protocol.get("schema_version") != "vuoro.outctl.study-protocol/v3":
        raise ContractValidationError("scenario launch requires study-protocol/v3")
    if protocol.get("repository_commit") != _repository_head(root):
        raise ContractValidationError("study protocol repository commit does not match HEAD")

    suite_path = _repository_file(root, protocol.get("scenario_suite_path"), "scenario suite")
    suite = validate_contract("scenario-suite", _read_json_object(suite_path, "scenario suite"))
    if suite.get("suite_digest") != protocol.get("scenario_suite_digest"):
        raise ContractValidationError("protocol and scenario suite canonical digests do not match")
    matrix_path = _repository_file(root, protocol.get("arm_matrix_path"), "arm matrix")
    matrix = validate_contract("arm-matrix", _read_json_object(matrix_path, "arm matrix"))
    if matrix.get("matrix_digest") != protocol.get("arm_matrix_digest"):
        raise ContractValidationError("protocol and arm matrix canonical digests do not match")

    selected = [item for item in suite["scenarios"] if item.get("scenario_id") == scenario_id]
    if len(selected) != 1:
        raise ContractValidationError(f"scenario ID is not bound exactly once: {scenario_id}")
    binding = selected[0]
    package_path = _bound_repository_file(root, binding["package"], "scenario package")
    fixture_path = _bound_repository_file(root, binding["fixture"], "scenario fixture")
    facts_path = _bound_repository_file(root, binding["expected_facts"], "expected facts")
    package = validate_contract(
        "scenario-package", _read_json_object(package_path, "scenario package")
    )
    facts = validate_contract("expected-facts", _read_json_object(facts_path, "expected facts"))
    if package.get("scenario_id") != scenario_id or facts.get("scenario_id") != scenario_id:
        raise ContractValidationError("scenario package/expected facts cross-binding mismatch")
    if package.get("scenario_class") != binding.get("scenario_class"):
        raise ContractValidationError("scenario package class contradicts suite binding")
    if package.get("fixture_digest") != binding["fixture"]["sha256"]:
        raise ContractValidationError("scenario package does not bind fixture bytes")
    if package.get("expected_facts_digest") != binding["expected_facts"]["sha256"]:
        raise ContractValidationError("scenario package does not bind expected-facts bytes")
    if package.get("mutation_authority_required") is True and not mutation_authorized:
        raise ContractValidationError("scenario requires mutation authority not granted to launch")
    return {
        "protocol": protocol,
        "suite": suite,
        "matrix": matrix,
        "package": package,
        "package_path": package_path,
        "fixture_path": fixture_path,
        "expected_facts_path": facts_path,
        "expected_facts": facts,
    }


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
        if value.get("schema_version") == "vuoro.outctl.study-protocol/v3":
            encoded = json.dumps(
                {key: item for key, item in value.items() if key != "protocol_digest"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            if len(encoded) > MAX_PROTOCOL_CANONICAL_BYTES:
                raise ContractValidationError(
                    "study protocol canonical bytes exceed the v3 initial limit "
                    f"of {MAX_PROTOCOL_CANONICAL_BYTES}"
                )
            if value.get("digest_scope") != "canonical-json-v1":
                raise ContractValidationError("study protocol v3 digest scope is unsupported")
    elif name == "scenario-package":
        requires = value.get("requires")
        if isinstance(requires, Mapping) and requires.get("mutation_authority") is not value.get(
            "mutation_authority_required"
        ):
            raise ContractValidationError(
                "scenario package mutation requirement must match requires.mutation_authority"
            )
    elif name == "scenario-suite":
        if value.get("suite_digest") != _canonical_digest(value, omit="suite_digest"):
            raise ContractValidationError("scenario suite digest does not bind canonical bytes")
        scenarios = value.get("scenarios")
        required = value.get("required_classes")
        if isinstance(scenarios, list) and isinstance(required, list):
            identifiers = [
                item.get("scenario_id") for item in scenarios if isinstance(item, Mapping)
            ]
            classes = [
                item.get("scenario_class") for item in scenarios if isinstance(item, Mapping)
            ]
            if len(identifiers) != len(set(identifiers)):
                raise ContractValidationError("scenario suite scenario IDs must be unique")
            if set(classes) != set(required):
                raise ContractValidationError(
                    "scenario suite scenarios must cover required_classes exactly"
                )
    elif name == "arm-matrix":
        if value.get("matrix_digest") != _canonical_digest(value, omit="matrix_digest"):
            raise ContractValidationError("arm matrix digest does not bind canonical bytes")
        arms = value.get("arms")
        contrasts = value.get("contrasts")
        arm_records = arms if isinstance(arms, list) else []
        contrast_records = contrasts if isinstance(contrasts, list) else []
        arm_ids = [arm.get("arm_id") for arm in arm_records if isinstance(arm, Mapping)]
        if len(arm_ids) != len(set(arm_ids)):
            raise ContractValidationError("arm matrix arm IDs must be unique")
        contrast_ids = [
            contrast.get("contrast_id")
            for contrast in contrast_records
            if isinstance(contrast, Mapping)
        ]
        if len(contrast_ids) != len(set(contrast_ids)):
            raise ContractValidationError("arm matrix contrast IDs must be unique")
        for contrast in contrast_records:
            if not isinstance(contrast, Mapping):
                continue
            if (
                contrast.get("treatment_arm") not in arm_ids
                or contrast.get("control_arm") not in arm_ids
            ):
                raise ContractValidationError("arm matrix contrast refers to an unknown arm")
    elif name == "study-suite":
        if value.get("suite_digest") != _canonical_digest(value, omit="suite_digest"):
            raise ContractValidationError("study suite digest does not bind canonical bytes")
        scenarios = value.get("scenarios")
        if isinstance(scenarios, list):
            identifiers = [
                item.get("scenario_id") for item in scenarios if isinstance(item, Mapping)
            ]
            classes = [
                item.get("scenario_class") for item in scenarios if isinstance(item, Mapping)
            ]
            required = {
                "healthy",
                "node-not-ready",
                "crashloop",
                "gitops-reconciliation-failure",
                "storage-failure",
                "warning-events",
            }
            if len(identifiers) != len(set(identifiers)):
                raise ContractValidationError("study suite scenario IDs must be unique")
            if set(classes) != required or len(classes) != len(required):
                raise ContractValidationError(
                    "study suite must bind exactly one scenario per required class"
                )
    elif name == "approved-command-policy":
        if value.get("policy_digest") != _canonical_digest(value, omit="policy_digest"):
            raise ContractValidationError("approved command policy digest mismatch")
        approved_classes = value.get("approved_classes")
        if isinstance(approved_classes, list):
            names = [
                item.get("command_class") for item in approved_classes if isinstance(item, Mapping)
            ]
            if len(names) != len(set(names)):
                raise ContractValidationError("approved command classes must be unique")
    elif name == "enforcement-observation":
        raw, exposed = value.get("raw_bytes"), value.get("exposed_bytes")
        if isinstance(raw, int) and isinstance(exposed, int):
            reduction = round((raw - exposed) * 1_000_000 / raw) if raw else None
            if value.get("reduction_ppm") != reduction:
                raise ContractValidationError("enforcement reduction does not reconcile")
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
        **{
            key: section("foundation").get(key) is True
            for key in ("schemas_valid", "policy_digest_stable", "full_repository_gate")
        },
        "evidence_ids": [],
    }
    result["mechanism"] = {
        **{
            key: section("mechanism").get(key) is True
            for key in ("passed", "process_semantics_passed", "security_passed")
        },
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
        **{
            key: shadow.get(key) is True
            for key in (
                "semantic_equivalence",
                "no_deadlocks",
                "recovery_verified",
                "overhead_acceptable",
            )
        },
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
