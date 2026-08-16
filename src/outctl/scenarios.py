"""Provider-neutral scenario resolution and deterministic test fixtures.

The acceptance harness used to know that every scenario was a Kubernetes JSON
fixture.  This module is the small boundary that lets a launcher work with
cluster replays, process fixtures, and future providers without making the
study compiler provider-aware.
"""

from __future__ import annotations

import hashlib
import json
import stat
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from outctl.contracts import ContractValidationError, validate_contract

MAX_FIXTURE_BYTES = 64 * 1024 * 1024
MAX_FIXTURE_COUNT = 1_000_000


class ScenarioHandlerError(ValueError):
    """Raised when a scenario cannot be resolved or materialized safely."""


@dataclass(frozen=True)
class ResolvedScenario:
    scenario_id: str
    provider: str
    package: dict[str, object]
    package_path: Path
    fixture_path: Path
    expected_facts_path: Path


@dataclass(frozen=True)
class MaterializedScenario:
    """Provider output consumed by a runner without shell interpolation."""

    scenario_id: str
    provider: str
    root: Path
    bin_path: Path
    environment: dict[str, str]

    @property
    def argv(self) -> tuple[str, ...]:
        return (str(self.bin_path),)


class ScenarioProvider(Protocol):
    provider_id: str

    def resolve(self, scenario: ResolvedScenario) -> ResolvedScenario: ...

    def materialize(self, scenario: ResolvedScenario, target: Path) -> MaterializedScenario: ...

    def teardown(self, materialized: MaterializedScenario) -> None: ...


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScenarioHandlerError(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ScenarioHandlerError(f"{label} must be a JSON object")
    return value


class ScenarioHandler:
    """Registry-backed handler independent of any study domain."""

    def __init__(self, providers: tuple[ScenarioProvider, ...] = ()) -> None:
        self._providers: dict[str, ScenarioProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: ScenarioProvider) -> None:
        if not provider.provider_id or provider.provider_id in self._providers:
            raise ScenarioHandlerError(
                f"provider ID is empty or already registered: {provider.provider_id!r}"
            )
        self._providers[provider.provider_id] = provider

    def provider(self, provider_id: str) -> ScenarioProvider:
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise ScenarioHandlerError(
                f"no scenario provider is registered for {provider_id!r}"
            ) from exc

    def resolve(self, binding: Mapping[str, object], repository_root: Path) -> ResolvedScenario:
        root = repository_root.resolve()

        def bound(raw: object, label: str) -> Path:
            if not isinstance(raw, Mapping):
                raise ScenarioHandlerError(f"{label} binding is missing")
            raw_path, expected = raw.get("path"), raw.get("sha256")
            if not isinstance(raw_path, str) or not raw_path or not isinstance(expected, str):
                raise ScenarioHandlerError(f"{label} binding is malformed")
            relative = Path(raw_path)
            path = (root / relative).resolve()
            if relative.is_absolute() or ".." in relative.parts or not path.is_relative_to(root):
                raise ScenarioHandlerError(f"{label} path escapes the repository")
            if not path.is_file() or _digest(path) != expected:
                raise ScenarioHandlerError(f"{label} digest mismatch or file is missing")
            return path

        package_path = bound(binding.get("package"), "scenario package")
        fixture_path = bound(binding.get("fixture"), "scenario fixture")
        facts_path = bound(binding.get("expected_facts"), "expected facts")
        try:
            package = validate_contract(
                "scenario-package", _read_object(package_path, "scenario package")
            )
            facts = validate_contract("expected-facts", _read_object(facts_path, "expected facts"))
        except ContractValidationError as exc:
            raise ScenarioHandlerError(str(exc)) from exc
        scenario_id, provider_id = package.get("scenario_id"), package.get("provider")
        if not isinstance(scenario_id, str) or not isinstance(provider_id, str):
            raise ScenarioHandlerError("scenario package has no usable ID/provider")
        if binding.get("scenario_id") != scenario_id or facts.get("scenario_id") != scenario_id:
            raise ScenarioHandlerError("suite, package, and expected facts disagree on scenario ID")
        fixture_binding = binding.get("fixture")
        facts_binding = binding.get("expected_facts")
        if not isinstance(fixture_binding, Mapping) or package.get(
            "fixture_digest"
        ) != fixture_binding.get("sha256"):
            raise ScenarioHandlerError("scenario package does not bind the suite fixture")
        if not isinstance(facts_binding, Mapping) or package.get(
            "expected_facts_digest"
        ) != facts_binding.get("sha256"):
            raise ScenarioHandlerError("scenario package does not bind expected facts")
        scenario = ResolvedScenario(
            scenario_id, provider_id, dict(package), package_path, fixture_path, facts_path
        )
        return self.provider(provider_id).resolve(scenario)

    def materialize(self, scenario: ResolvedScenario, target: Path) -> MaterializedScenario:
        return self.provider(scenario.provider).materialize(scenario, target)

    def teardown(self, materialized: MaterializedScenario) -> None:
        self.provider(materialized.provider).teardown(materialized)


def _fixture(path: Path) -> dict[str, object]:
    value = _read_object(path, "process fixture")
    if value.get("provider") != "process-fixture":
        raise ScenarioHandlerError("process fixture provider marker is missing")
    operation = value.get("operation")
    if operation not in {"stdout_lines", "repeat", "progress", "giant_line", "raw_bytes", "mixed"}:
        raise ScenarioHandlerError(f"unsupported process fixture operation: {operation!r}")
    return value


def _count(value: object, name: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= MAX_FIXTURE_COUNT
    ):
        raise ScenarioHandlerError(f"{name} must be an integer in the bounded fixture range")
    return value


class ProcessFixtureProvider:
    """Materialize a declarative process fixture for CI and handler tests."""

    provider_id = "process-fixture"

    def resolve(self, scenario: ResolvedScenario) -> ResolvedScenario:
        spec = _fixture(scenario.fixture_path)
        operation = spec["operation"]
        if operation in {"stdout_lines", "repeat", "progress"}:
            _count(spec.get("count"), "count")
        elif operation == "mixed":
            _count(spec.get("stdout_count"), "stdout_count")
            _count(spec.get("stderr_count"), "stderr_count")
        elif operation == "giant_line":
            size = _count(spec.get("bytes"), "bytes")
            if size > MAX_FIXTURE_BYTES:
                raise ScenarioHandlerError("giant line exceeds the process fixture byte limit")
            byte = spec.get("byte", "x")
            if not isinstance(byte, str) or len(byte.encode()) != 1:
                raise ScenarioHandlerError("giant line byte must encode to exactly one byte")
        elif operation == "raw_bytes":
            raw = spec.get("hex")
            if not isinstance(raw, str) or len(raw) % 2 or len(raw) // 2 > MAX_FIXTURE_BYTES:
                raise ScenarioHandlerError("raw byte fixture is invalid or too large")
            try:
                bytes.fromhex(raw)
            except ValueError as exc:
                raise ScenarioHandlerError("raw byte fixture is not hexadecimal") from exc
        exit_code = spec.get("exit_code", 0)
        if (
            not isinstance(exit_code, int)
            or isinstance(exit_code, bool)
            or not 0 <= exit_code <= 255
        ):
            raise ScenarioHandlerError("exit_code must be between 0 and 255")
        return scenario

    def materialize(self, scenario: ResolvedScenario, target: Path) -> MaterializedScenario:
        spec = _fixture(scenario.fixture_path)
        self.resolve(scenario)
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(stat.S_IRWXU)
        executable = target / "scenario-fixture"
        encoded = json.dumps(spec, sort_keys=True, separators=(",", ":"))
        script = textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import json
            import sys
            SPEC = json.loads({encoded!r})
            OP = SPEC["operation"]
            EXIT = SPEC.get("exit_code", 0)
            def emit(value, stream):
                stream.buffer.write(value)
                stream.buffer.flush()
            if OP == "stdout_lines":
                template = SPEC.get("line_template", "line-{{index}}")
                marker = SPEC.get("marker")
                for index in range(SPEC["count"]):
                    line = template.format(index=index)
                    if marker is not None and index == SPEC.get("marker_index", SPEC["count"] // 2):
                        line += str(marker)
                    emit((line + "\\n").encode(), sys.stdout)
            elif OP == "repeat":
                emit(((SPEC.get("line", "") + "\\n") * SPEC["count"]).encode(), sys.stdout)
            elif OP == "progress":
                for index in range(SPEC["count"]):
                    emit(("progress " + str(index) + "\\r").encode(), sys.stdout)
                emit((SPEC.get("final", "done") + "\\n").encode(), sys.stdout)
            elif OP == "giant_line":
                emit((SPEC.get("byte", "x") * SPEC["bytes"]).encode(), sys.stdout)
            elif OP == "raw_bytes":
                emit(bytes.fromhex(SPEC.get("hex", "")), sys.stdout)
            elif OP == "mixed":
                for index in range(max(SPEC["stdout_count"], SPEC["stderr_count"])):
                    if index < SPEC["stdout_count"]:
                        emit(("stdout-" + str(index) + "\\n").encode(), sys.stdout)
                    if index < SPEC["stderr_count"]:
                        emit(("stderr-" + str(index) + "\\n").encode(), sys.stderr)
            raise SystemExit(EXIT)
            """
        )
        executable.write_text(script, encoding="utf-8")
        executable.chmod(stat.S_IRWXU)
        return MaterializedScenario(
            scenario.scenario_id,
            self.provider_id,
            target,
            executable,
            {"OUTCTL_SCENARIO_ID": scenario.scenario_id},
        )

    def teardown(self, materialized: MaterializedScenario) -> None:
        return None


class KubernetesReplayProvider:
    """Provider boundary for the existing digest-bound kubectl replay."""

    provider_id = "kubernetes-replay"

    def resolve(self, scenario: ResolvedScenario) -> ResolvedScenario:
        value = _read_object(scenario.fixture_path, "Kubernetes replay fixture")
        if not value:
            raise ScenarioHandlerError("Kubernetes replay fixture is empty")
        return scenario

    def materialize(self, scenario: ResolvedScenario, target: Path) -> MaterializedScenario:
        self.resolve(scenario)
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(stat.S_IRWXU)
        executable = target / "kubectl"
        fixture, digest = str(scenario.fixture_path), str(scenario.package["fixture_digest"])
        script = textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import hashlib, json, sys
            from pathlib import Path
            path = Path({fixture!r})
            body = path.read_bytes()
            if "sha256:" + hashlib.sha256(body).hexdigest() != {digest!r}:
                print("fixture digest mismatch", file=sys.stderr); raise SystemExit(64)
            fixture = json.loads(body)
            argv = tuple(sys.argv[1:])
            if argv == ("version", "-o", "json"):
                result = {{
                    "clientVersion": {{"gitVersion": "v1.34.0-replay"}},
                    "serverVersion": {{"gitVersion": "v1.34.0-replay"}},
                    "api": fixture.get("api"),
                }}
            elif argv == ("get", "nodes", "-o", "wide"):
                result = {{"items": fixture.get("nodes", [])}}
            elif argv == ("get", "pods", "-A", "-o", "wide"):
                result = {{"items": fixture.get("pods", [])}}
            elif argv == ("-n", "flux-system", "get", "pods", "-o", "wide"):
                result = {{"items": [fixture.get("gitops", {{}})]}}
            elif argv == ("-n", "gatus", "get", "deployments,persistentvolumeclaims"):
                result = {{
                    "deployments": [{{"name": "gatus", "ready": True}}],
                    "persistentvolumeclaims": [fixture.get("storage", {{}})],
                }}
            elif argv == ("-n", "gatus", "get", "events", "--sort-by=.lastTimestamp"):
                result = {{"items": fixture.get("events", [])}}
            else:
                result = None
            if result is None:
                print("command is outside the frozen replay corpus", file=sys.stderr)
                raise SystemExit(64)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            """
        )
        executable.write_text(script, encoding="utf-8")
        executable.chmod(stat.S_IRWXU)
        return MaterializedScenario(
            scenario.scenario_id,
            self.provider_id,
            target,
            executable,
            {"OUTCTL_SCENARIO_ID": scenario.scenario_id},
        )

    def teardown(self, materialized: MaterializedScenario) -> None:
        return None


TestScenarioHandler = ScenarioHandler
ProcessFixtureHandler = ProcessFixtureProvider
