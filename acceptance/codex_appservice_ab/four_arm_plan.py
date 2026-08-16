"""Frozen planning contract for the next four-arm characterization run."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Arm:
    arm_id: str
    capture: str
    projection: str
    tool_surface: str = "normal-command"


FOUR_ARM_MATRIX: tuple[Arm, ...] = (
    Arm("A", "none", "native-codex-truncation"),
    Arm("B", "outctl", "exact-native-like"),
    Arm("C", "outctl", "generic-bounded"),
    Arm("D", "outctl", "semantic-pods"),
)


def plan_payload() -> dict[str, Any]:
    """Return a raw-free matrix suitable for a dry-run report."""

    return {
        "schema_version": "vuoro.outctl.four-arm-plan/v1",
        "arms": [asdict(arm) for arm in FOUR_ARM_MATRIX],
        "held_constant": [
            "prompt",
            "instruction surface",
            "model",
            "reasoning setting",
            "output schema",
            "command text",
            "normal command tool surface",
        ],
        "primary_contrasts": {
            "capture_overhead": "B_vs_A",
            "generic_projection": "C_vs_B",
            "semantic_projection": "D_vs_C",
            "total_product": "D_vs_A",
        },
        "launcher": "outctl.harness.Launcher",
    }


def arm_matrix_payload() -> dict[str, Any]:
    """Return the sealed v1 matrix consumed by the reusable N-arm launcher."""

    value: dict[str, Any] = {
        "schema_version": "vuoro.outctl.arm-matrix/v1",
        "matrix_id": "codex-appservice-four-arm-v1",
        "matrix_digest": "",
        "arms": [asdict(arm) for arm in FOUR_ARM_MATRIX],
        "contrasts": [
            {"contrast_id": "capture_overhead", "treatment_arm": "B", "control_arm": "A"},
            {"contrast_id": "generic_projection", "treatment_arm": "C", "control_arm": "B"},
            {"contrast_id": "semantic_projection", "treatment_arm": "D", "control_arm": "C"},
            {"contrast_id": "total_product", "treatment_arm": "D", "control_arm": "A"},
        ],
        "held_constant": [
            "prompt",
            "instruction surface",
            "model",
            "reasoning setting",
            "output schema",
            "command text",
            "normal command tool surface",
        ],
    }
    body = {key: item for key, item in value.items() if key != "matrix_digest"}
    value["matrix_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )
    return value


def validate_plan(arms: tuple[Arm, ...] = FOUR_ARM_MATRIX) -> None:
    """Fail closed if a future launcher changes the contrast matrix."""

    if tuple(arm.arm_id for arm in arms) != ("A", "B", "C", "D"):
        raise ValueError("four-arm plan must contain A, B, C, D in order")
    if any(arm.tool_surface != "normal-command" for arm in arms):
        raise ValueError("all four arms must use the same normal command surface")
    if arms[0].capture != "none" or any(arm.capture != "outctl" for arm in arms[1:]):
        raise ValueError("capture contrast must be none versus outctl")
    if arms[1].projection != "exact-native-like":
        raise ValueError("arm B must isolate exact/native-like pass-through")
    if arms[2].projection != "generic-bounded" or arms[3].projection != "semantic-pods":
        raise ValueError("arms C and D must isolate generic and semantic projection")
