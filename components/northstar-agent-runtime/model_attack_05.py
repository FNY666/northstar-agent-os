"""Model attack 05: model inversion detection (MOCK), Simulated.

Detects query batches consistent with gradient-free model inversion:
many near-identical inputs with tiny perturbations (character swaps,
synonym nudges, numeric jitter) aimed at reconstructing a training
sample or a hidden attribute.

This is a MOCK: real inversion needs output-confidence access and
optimization loops. The behavioral signature (perturbation batches)
is what an API boundary can see.

What this IS: perturbation-batch detection over a query log.
What this IS NOT: not a reconstruction; does not recover data.
"""

from __future__ import annotations

import ast
import difflib
from typing import List, Tuple

MODEL_ATTACK_05_VERSION = "model-attack-05.v1"

SCHEMA_PIN = "northstar.model-attack-05.v1"

#: Batch of this many near-identical queries -> flag.
BATCH_THRESHOLD = 8

#: Sequence similarity ratio to count as a perturbation of the base.
PERTURBATION_SIMILARITY = 0.85


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


def detect_inversion_batch(queries: List[str]) -> Tuple[bool, str]:
    """Analyze a query log. Returns (flagged, reason)."""
    if not isinstance(queries, list) or not all(
        isinstance(q, str) for q in queries
    ):
        raise ModelAttackError("queries must be a list of str")
    if len(queries) < BATCH_THRESHOLD:
        return False, "clean"
    base = queries[0]
    perturbed = 0
    for q in queries[1:]:
        ratio = difflib.SequenceMatcher(None, base, q).ratio()
        if PERTURBATION_SIMILARITY <= ratio < 1.0:
            perturbed += 1
    if perturbed >= BATCH_THRESHOLD - 1:
        return True, f"perturbation batch: {perturbed + 1} near-identical queries"
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
    base = "The user's face is described as having blue eyes"
    batch = [base]
    for i in range(9):
        batch.append(base + f" variant{i}")
    flagged, _ = detect_inversion_batch(batch)
    assert flagged is True
    flagged, _ = detect_inversion_batch(["a", "b", "c"])
    assert flagged is False
    try:
        detect_inversion_batch([1, 2])  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-05 OK (mock)")


if __name__ == "__main__":
    main()
