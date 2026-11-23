"""Model attack 08: data poisoning detection (MOCK), Simulated.

Detects poisoned samples in a training/fine-tuning batch using the
clean-label heuristic: near-duplicate inputs carrying conflicting
labels, and label distributions that flip on paraphrases of the same
content.

This is a MOCK: real poisoning detection needs influence functions
or certified training. The duplicate-with-conflict heuristic catches
the cheapest, most common poisoning pattern at data-ingest time.

What this IS: ingest-time duplicate/conflict screening.
What this IS NOT: not a defense against gradient-level poisoning.
"""

from __future__ import annotations

import ast
import difflib
from typing import Dict, List, Tuple

MODEL_ATTACK_08_VERSION = "model-attack-08.v1"

SCHEMA_PIN = "northstar.model-attack-08.v1"

#: Similarity above which two samples count as near-duplicates.
DUP_SIMILARITY = 0.9


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


def detect_poisoned_batch(
    samples: List[Dict[str, str]],
) -> Tuple[bool, str]:
    """Each sample: {"text": str, "label": str}. Returns (flagged, reason)."""
    if not isinstance(samples, list):
        raise ModelAttackError("samples must be a list")
    for s in samples:
        if (
            not isinstance(s, dict)
            or not isinstance(s.get("text"), str)
            or not isinstance(s.get("label"), str)
        ):
            raise ModelAttackError("each sample needs str text and label")
    conflicts: List[Tuple[int, int]] = []
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            ratio = difflib.SequenceMatcher(
                None, samples[i]["text"], samples[j]["text"]
            ).ratio()
            if ratio >= DUP_SIMILARITY and samples[i]["label"] != samples[j]["label"]:
                conflicts.append((i, j))
    if conflicts:
        i, j = conflicts[0]
        return True, (
            f"label conflict on near-duplicates: sample {i} vs {j} "
            f"({samples[i]['label']!r} vs {samples[j]['label']!r})"
        )
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "difflib", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    flagged, _ = detect_poisoned_batch(
        [
            {"text": "This movie was great", "label": "positive"},
            {"text": "This movie was great!", "label": "negative"},
        ]
    )
    assert flagged is True
    flagged, _ = detect_poisoned_batch(
        [
            {"text": "This movie was great", "label": "positive"},
            {"text": "The weather is nice", "label": "neutral"},
        ]
    )
    assert flagged is False
    try:
        detect_poisoned_batch([{"text": 1, "label": "x"}])  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-08 OK (mock)")


if __name__ == "__main__":
    main()
