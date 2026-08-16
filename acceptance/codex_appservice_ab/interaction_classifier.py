"""Raw-free interaction characterization for controlled harness traces.

The classifier deliberately reports observed interaction shapes and uses
``unknown`` when a causal label is not directly supported.  It is a
characterization aid, not a validated causal model.  Evaluation requires a
manually labelled corpus supplied by the caller.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

CAUSES = frozenset(
    {
        "retrieval",
        "duplicate_command",
        "absence_confirmation",
        "unknown",
    }
)
_RETRIEVAL = re.compile(r"(?:outctl-health|outctl_kubectl_router\.py)\s+(?:tail|search)")
_ABSENCE = re.compile(r"\b(?:get|list)\s+(?:pods|deployments|events|nodes)\b")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _command_items(events: Sequence[Mapping[str, Any]]) -> list[tuple[int, Mapping[str, Any]]]:
    return [
        (event_index, item)
        for event_index, event in enumerate(events)
        if event.get("type") == "item.completed"
        and isinstance(event.get("item"), Mapping)
        and event["item"].get("type") == "command_execution"
        for item in [event["item"]]
    ]


def classify_trace(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify command interaction shapes without retaining command text."""

    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for ordinal, (event_index, item) in enumerate(_command_items(events), start=1):
        command = item.get("command") if isinstance(item.get("command"), str) else ""
        command_hash = _sha256(command)
        folded = command.casefold()
        if _RETRIEVAL.search(folded):
            cause, confidence = "retrieval", "high"
        elif command_hash in seen:
            cause, confidence = "duplicate_command", "high"
        elif _ABSENCE.search(folded):
            # The command shape is observed.  Whether it was unnecessary or
            # caused by a missing projection is not observable here.
            cause, confidence = "unknown", "low"
        else:
            cause, confidence = "unknown", "low"
        seen.add(command_hash)
        records.append(
            {
                "command_ordinal": ordinal,
                "event_index": event_index,
                "command_sha256": command_hash,
                "cause": cause,
                "confidence": confidence,
                "needed_for_task": None,
                "could_initial_projection_have_answered": None,
            }
        )
    cause_counts = Counter(record["cause"] for record in records)
    return {
        "classifier": "interaction-shape/v1",
        "records": records,
        "counts": dict(sorted(cause_counts.items())),
        "unclassified_count": sum(record["cause"] == "unknown" for record in records),
        "causal_ground_truth": "not_present",
    }


def evaluate_labeled_traces(
    predicted: Sequence[Mapping[str, Any]],
    labels: Sequence[str],
    *,
    alternate_labels: Sequence[Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Evaluate predictions against a manual label sequence.

    Missing or invalid labels fail closed.  ``alternate_labels`` is optional
    inter-rater data for the same records; disagreement is reported rather
    than hidden behind a forced consensus.
    """

    if len(predicted) != len(labels):
        raise ValueError("predicted records and labels must have equal length")
    if any(label not in CAUSES for label in labels):
        raise ValueError("labels contain an unsupported cause")
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    for record, label in zip(predicted, labels, strict=True):
        cause = record.get("cause")
        if cause not in CAUSES:
            raise ValueError("prediction contains an unsupported cause")
        confusion[label][cause] += 1
    per_cause: dict[str, dict[str, float | int | None]] = {}
    for cause in sorted(CAUSES):
        true_positive = confusion[cause][cause]
        predicted_positive = sum(row[cause] for row in confusion.values())
        actual_positive = sum(confusion[cause].values())
        per_cause[cause] = {
            "precision": true_positive / predicted_positive if predicted_positive else None,
            "recall": true_positive / actual_positive if actual_positive else None,
            "support": actual_positive,
        }
    disagreements = 0
    if alternate_labels is not None:
        for index, raters in enumerate(alternate_labels):
            if len(raters) < 2 or any(label not in CAUSES for label in raters):
                raise ValueError(f"alternate labels at index {index} are invalid")
            disagreements += len(set(raters)) > 1
    correct = sum(confusion[cause][cause] for cause in CAUSES)
    return {
        "evaluation": "manual-labels-required/v1",
        "sample_count": len(labels),
        "accuracy": correct / len(labels) if labels else None,
        "precision_recall_by_cause": per_cause,
        "confusion_matrix": {
            actual: dict(sorted(row.items())) for actual, row in sorted(confusion.items())
        },
        "unclassified_rate": sum(label == "unknown" for label in labels) / len(labels)
        if labels
        else None,
        "ambiguous_rate": sum(
            record.get("confidence") == "low" for record in predicted
        )
        / len(predicted)
        if predicted
        else None,
        "inter_rater_disagreement_count": disagreements,
        "status": "validated_against_manual_labels" if labels else "scaffold",
    }

