"""Durable, raw-free observation records backed by existing captures.

The command runner remains a compatibility adapter.  Native harnesses can
instead import their completed stdout/stderr artifacts or ingest metadata for
an already captured result.  Observation records contain stable artifact
references and provenance, never the raw bodies or local filesystem paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from outctl.retrieval import RetrievalStatus, inspect_capture, verify_capture

OBSERVATION_SCHEMA_VERSION = "vuoro.outctl.observation/v1"
_OBSERVATION_ID = re.compile(r"^obs-[a-f0-9]{64}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class ObservationError(ValueError):
    """Raised when observation metadata or backing evidence is unsafe."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _schema() -> dict[str, Any]:
    packaged = files("outctl").joinpath("schemas", "observation.schema.json")
    development = Path(__file__).parents[2] / "schemas" / "observation.schema.json"
    text = packaged.read_text(encoding="utf-8") if packaged.is_file() else development.read_text()
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ObservationError("observation schema root must be an object")
    return value


def _validate(value: Mapping[str, Any]) -> dict[str, Any]:
    validator = Draft202012Validator(_schema())
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
    if errors:
        raise ObservationError(errors[0].message)
    return dict(value)


def _ensure_root(root: Path) -> None:
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise ObservationError("spool root is not a safe directory")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    observations = root / "observations"
    if observations.exists() and (observations.is_symlink() or not observations.is_dir()):
        raise ObservationError("observation directory is not safe")
    observations.mkdir(mode=0o700, exist_ok=True)
    os.chmod(observations, 0o700)


def _safe_regular_file(path: Path) -> None:
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise ObservationError(f"artifact is unavailable: {path}") from error
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        raise ObservationError(f"artifact is not a regular file: {path}")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ObservationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ObservationError(f"{label} must be a bounded non-empty string")
    return value


def _optional_text(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _capture_metadata(root: Path, capture_id: str) -> dict[str, Any]:
    inspected = inspect_capture(root, capture_id)
    if inspected.status is not RetrievalStatus.AVAILABLE or inspected.manifest is None:
        raise ObservationError(f"capture {capture_id!r} is not available: {inspected.detail}")
    verified = verify_capture(root, capture_id)
    if verified.status is not RetrievalStatus.AVAILABLE:
        raise ObservationError(f"capture {capture_id!r} failed verification: {verified.detail}")
    manifest_path = root / "captures" / capture_id / "manifest.json"
    _safe_regular_file(manifest_path)
    manifest = dict(inspected.manifest)
    streams = manifest.get("streams")
    if not isinstance(streams, Mapping):
        raise ObservationError("capture manifest has no stream metadata")
    stream_data: dict[str, dict[str, Any]] = {}
    for name in ("stdout", "stderr"):
        stream = streams.get(name)
        if not isinstance(stream, Mapping):
            raise ObservationError(f"capture manifest has no {name} metadata")
        size = stream.get("bytes")
        digest = stream.get("sha256")
        if not isinstance(size, int) or size < 0:
            raise ObservationError(f"capture {name} byte count is invalid")
        stream_data[name] = {"bytes": size, "sha256": _digest(digest, f"{name}.sha256")}
    manifest_digest = _sha256_file(manifest_path)
    return {
        "capture_id": capture_id,
        "manifest_sha256": manifest_digest,
        "capture_ref": f"outctl://capture/{capture_id}/manifest/sha256/{manifest_digest}",
        "streams": stream_data,
    }


def _artifact_ref(digest: str) -> str:
    return f"artifact:sha256:{digest}"


def _observation_record(
    capture: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    source_value = metadata.get("source")
    invocation_value = metadata.get("invocation")
    result_value = metadata.get("result")
    if not isinstance(source_value, Mapping):
        raise ObservationError("observation source must be an object")
    if not isinstance(invocation_value, Mapping):
        raise ObservationError("observation invocation must be an object")
    if not isinstance(result_value, Mapping):
        raise ObservationError("observation result must be an object")

    source = {
        "harness": _text(source_value.get("harness"), "source.harness"),
        "session": _text(source_value.get("session"), "source.session"),
        "tool_call": _text(source_value.get("tool_call"), "source.tool_call"),
    }
    invocation = {
        "tool": _text(invocation_value.get("tool"), "invocation.tool"),
        "command_sha256": _digest(
            invocation_value.get("command_sha256"), "invocation.command_sha256"
        ),
    }
    exit_code = result_value.get("exit_code")
    if not isinstance(exit_code, int) and exit_code is not None:
        raise ObservationError("result.exit_code must be an integer or null")
    duration_ms = result_value.get("duration_ms")
    if not isinstance(duration_ms, int) or duration_ms < 0:
        raise ObservationError("result.duration_ms must be a non-negative integer")
    streams = capture["streams"]
    assert isinstance(streams, Mapping)
    stdout = streams["stdout"]
    stderr = streams["stderr"]
    assert isinstance(stdout, Mapping) and isinstance(stderr, Mapping)
    result = {
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": _artifact_ref(str(stdout["sha256"])),
        "stderr": _artifact_ref(str(stderr["sha256"])),
    }
    identity = {
        "capture_manifest_sha256": capture["manifest_sha256"],
        "source": source,
        "invocation": invocation,
        "result": result,
    }
    observation_id = "obs-" + hashlib.sha256(_canonical(identity)).hexdigest()
    record = {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "observation_id": observation_id,
        "created_at": created_at or _utc_now(),
        "capture_id": capture["capture_id"],
        "capture_ref": capture["capture_ref"],
        "capture_manifest_sha256": capture["manifest_sha256"],
        "source": source,
        "invocation": invocation,
        "result": result,
    }
    return _validate(record)


def _observation_path(root: Path, observation_id: str) -> Path:
    if not _OBSERVATION_ID.fullmatch(observation_id):
        raise ObservationError("invalid observation id")
    return root / "observations" / f"{observation_id}.json"


def _write_immutable(root: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    _ensure_root(root)
    path = _observation_path(root, str(record["observation_id"]))
    payload = json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if path.exists():
        _safe_regular_file(path)
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing != record:
            if not isinstance(existing, dict):
                raise ObservationError("observation id collision with different content")
            comparable_existing = {
                key: value for key, value in existing.items() if key != "created_at"
            }
            comparable_record = {key: value for key, value in record.items() if key != "created_at"}
            if comparable_existing != comparable_record:
                raise ObservationError("observation id collision with different content")
            return _validate(existing)
        return dict(record)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return dict(record)


def ingest_observation(
    root: Path, capture_id: str, metadata: Mapping[str, Any]
) -> dict[str, Any]:
    """Create or verify one immutable observation for an existing capture."""
    capture = _capture_metadata(root, capture_id)
    return _write_immutable(root, _observation_record(capture, metadata))


def _import_capture(
    root: Path,
    stdout_path: Path,
    stderr_path: Path | None,
    *,
    exit_code: int | None,
) -> dict[str, Any]:
    _ensure_root(root)
    _safe_regular_file(stdout_path)
    if stderr_path is not None:
        _safe_regular_file(stderr_path)
    captures = root / "captures"
    captures.mkdir(mode=0o700, exist_ok=True)
    os.chmod(captures, 0o700)
    capture_id = "import-" + uuid.uuid4().hex
    temporary = Path(tempfile.mkdtemp(prefix=f".{capture_id}.", dir=str(captures)))
    os.chmod(temporary, 0o700)
    try:
        stdout_target = temporary / "stdout.raw"
        stderr_target = temporary / "stderr.raw"
        events_target = temporary / "events.ndjson"
        shutil.copyfile(stdout_path, stdout_target)
        if stderr_path is None:
            stderr_target.write_bytes(b"")
        else:
            shutil.copyfile(stderr_path, stderr_target)
        events_target.write_bytes(b"")
        for path in (stdout_target, stderr_target, events_target):
            os.chmod(path, 0o600)
        manifest = {
            "capture_id": capture_id,
            "capture_status": "COMPLETE",
            "command": {
                "started": True,
                "exit_code": exit_code,
                "signal": None,
                "timed_out": False,
                "cancelled": False,
            },
            "streams": {
                "stdout": {
                    "bytes": stdout_target.stat().st_size,
                    "sha256": _sha256_file(stdout_target),
                },
                "stderr": {
                    "bytes": stderr_target.stat().st_size,
                    "sha256": _sha256_file(stderr_target),
                },
            },
            "event_index": {"events": 0, "sha256": _sha256_file(events_target)},
        }
        manifest_path = temporary / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        final = captures / capture_id
        os.replace(temporary, final)
        return {"capture_id": capture_id}
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def import_observation(
    root: Path,
    stdout_path: Path,
    stderr_path: Path | None,
    metadata: Mapping[str, Any],
    *,
    exit_code: int | None,
) -> dict[str, Any]:
    """Import external completed artifacts, then create their observation."""
    imported = _import_capture(root, stdout_path, stderr_path, exit_code=exit_code)
    return ingest_observation(root, str(imported["capture_id"]), metadata)


def read_observation(root: Path, observation_id: str) -> dict[str, Any]:
    _ensure_root(root)
    path = _observation_path(root, observation_id)
    if not path.exists():
        raise ObservationError("observation is unavailable")
    _safe_regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ObservationError("observation is unreadable") from error
    if not isinstance(value, dict):
        raise ObservationError("observation is not an object")
    return _validate(value)


def observation_capture_id(root: Path, observation_id: str) -> str:
    value = read_observation(root, observation_id)
    capture_id = value.get("capture_id")
    if not isinstance(capture_id, str):
        raise ObservationError("observation has no capture binding")
    return capture_id


def _action_path(root: Path) -> Path:
    _ensure_root(root)
    path = root / "observation-actions.jsonl"
    if path.exists():
        _safe_regular_file(path)
    return path


def _actions(root: Path, observation_id: str) -> list[dict[str, Any]]:
    path = _action_path(root)
    if not path.exists():
        return []
    result: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if isinstance(value, dict) and value.get("observation_id") == observation_id:
            result.append(value)
    return result


def record_observation_action(
    root: Path, observation_id: str, action: str, reason: str | None
) -> dict[str, Any]:
    read_observation(root, observation_id)
    if action not in {"pin", "promote"}:
        raise ObservationError("unsupported observation action")
    bounded_reason = _optional_text(reason, "reason")
    record = {
        "schema_version": "vuoro.outctl.observation-action/v1",
        "action_id": uuid.uuid4().hex,
        "observation_id": observation_id,
        "action": action,
        "reason": bounded_reason
        or ("promoted evidence" if action == "promote" else "pinned evidence"),
        "occurred_at": _utc_now(),
    }
    path = _action_path(root)
    with path.open("a", encoding="utf-8") as handle:
        os.chmod(path, 0o600)
        handle.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
    return record


def observation_summary(root: Path, observation_id: str) -> dict[str, Any]:
    value = read_observation(root, observation_id)
    actions = _actions(root, observation_id)
    capture = _capture_metadata(root, str(value["capture_id"]))
    return {
        **value,
        "capture": {
            "stdout_bytes": capture["streams"]["stdout"]["bytes"],
            "stderr_bytes": capture["streams"]["stderr"]["bytes"],
            "verified": True,
        },
        "retention": actions[-1] if actions else {"state": "temporary"},
    }


def compare_observations(root: Path, left_id: str, right_id: str) -> dict[str, Any]:
    left = observation_summary(root, left_id)
    right = observation_summary(root, right_id)
    left_result = left["result"]
    right_result = right["result"]
    assert isinstance(left_result, Mapping) and isinstance(right_result, Mapping)
    streams = {}
    for name in ("stdout", "stderr"):
        streams[name] = {
            "same": left_result.get(name) == right_result.get(name),
            "left": left_result.get(name),
            "right": right_result.get(name),
        }
    return {
        "status": "AVAILABLE",
        "left": left_id,
        "right": right_id,
        "same_result": (
            left_result.get("exit_code") == right_result.get("exit_code")
            and all(value["same"] is True for value in streams.values())
        ),
        "streams": streams,
    }
