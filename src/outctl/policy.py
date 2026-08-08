"""Output policy resolution and deterministic digest computation.

Policies are maintained in Git as YAML policy sets.  A resolved policy is a
complete ``OutputPolicy`` produced by applying inline overrides on top of any
``extends`` chain.  Its digest is the SHA-256 of the canonical JSON
serialization of the resolved policy.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import jsonschema  # type: ignore[import-untyped]
import yaml  # type: ignore[import-untyped]

from outctl.models import OutputPolicy, OutputPolicySet
from outctl.serialization import canonical_sha256


class PolicyError(Exception):
    """Raised when a policy cannot be resolved or validated."""


class PolicyValidationError(PolicyError):
    """Raised when a policy set fails schema-backed validation."""


class PolicyNotFoundError(PolicyError):
    """Raised when a referenced policy name does not exist in the set."""


class PolicyCycleError(PolicyError):
    """Raised when an ``extends`` chain contains a cycle."""


# Sections that can appear under ``spec.policies.<name>`` and be merged.
_POLICY_SECTIONS = (
    "capture",
    "budget",
    "projection",
    "redaction",
    "security",
    "retention",
    "replica",
)

# Repository-local schema for the checked-in OutputPolicySet contract.
_POLICY_SET_SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "output-policy-set.schema.json"


def _policy_set_schema() -> dict[str, Any]:
    """Load and return the OutputPolicySet JSON schema."""
    text = _POLICY_SET_SCHEMA_PATH.read_text(encoding="utf-8")
    return cast(dict[str, Any], json.loads(text))


def validate_policy_set_data(data: Mapping[str, Any]) -> None:
    """Validate raw OutputPolicySet data against the checked-in schema.

    Raises ``PolicyValidationError`` for unknown apiVersions, wrong kinds, or
    any other structural violation of the OutputPolicySet contract.  This is
    performed before converting the data into typed models so that invalid
    inputs fail closed.
    """
    try:
        jsonschema.Draft202012Validator(_policy_set_schema()).validate(dict(data))
    except jsonschema.ValidationError as exc:
        raise PolicyValidationError(f"policy set schema validation failed: {exc.message}") from exc


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into ``base`` without mutating inputs."""
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def load_policy_set(path: str | Path) -> OutputPolicySet:
    """Load a YAML ``OutputPolicySet`` from ``path`` and return a typed model.

    The raw YAML is first validated against the checked-in OutputPolicySet
    schema; any violation raises ``PolicyValidationError`` before a typed model
    is produced.
    """
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise PolicyError(f"policy set file {path!r} did not contain a mapping")
    validate_policy_set_data(data)
    return OutputPolicySet.from_dict(data)


def resolve_policy(
    policy_set: OutputPolicySet,
    name: str,
    _chain: set[str] | None = None,
) -> OutputPolicy:
    """Resolve ``name`` from ``policy_set`` into a complete ``OutputPolicy``.

    The resolution follows the ``extends`` chain, deep-merging each inline
    policy override onto its base.  Cycles raise ``PolicyCycleError``;
    missing policies raise ``PolicyNotFoundError``.
    """
    chain = _chain or set()
    if name in chain:
        raise PolicyCycleError(" -> ".join([*sorted(chain), name]))
    chain = chain | {name}

    inline_policies = policy_set.spec.policies
    if name not in inline_policies:
        raise PolicyNotFoundError(f"policy {name!r} not found in policy set")

    inline = inline_policies[name]
    inline_dict = inline.to_dict()

    base_spec: dict[str, Any] = {}
    if inline.extends:
        base_policy = resolve_policy(policy_set, inline.extends, chain)
        base_spec = deepcopy(base_policy.to_dict().get("spec", {}))

    resolved_spec: dict[str, Any] = deepcopy(base_spec)
    for section in _POLICY_SECTIONS:
        if section in inline_dict:
            resolved_spec[section] = _deep_merge(
                resolved_spec.get(section, {}),
                inline_dict[section],
            )

    resolved_data: dict[str, Any] = {
        "apiVersion": "vuoro.outctl/v1alpha1",
        "kind": "OutputPolicy",
        "metadata": {"name": name},
        "spec": resolved_spec,
    }

    return OutputPolicy.from_dict(resolved_data)


def policy_digest(policy: OutputPolicy) -> str:
    """Return the canonical ``sha256:<hex>`` digest of ``policy``."""
    return f"sha256:{canonical_sha256(policy.to_dict())}"


def resolve_and_digest(policy_set: OutputPolicySet, name: str) -> tuple[OutputPolicy, str]:
    """Resolve a policy and return both the model and its canonical digest."""
    resolved = resolve_policy(policy_set, name)
    return resolved, policy_digest(resolved)
