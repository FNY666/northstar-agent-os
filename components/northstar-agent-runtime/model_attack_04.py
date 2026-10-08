"""Model attack 04: membership inference detection (MOCK), Simulated.

Detects query patterns consistent with membership inference: repeated
probing of the same (or near-duplicate) data point with small
variations, shadow-model style A/B comparisons, and confidence
harvesting ("how confident are you that X was in training?").

This is a MOCK: true MI needs model internals (loss values). The
query-log heuristics here catch the behavioral signature at the
API boundary.

What this IS: query-pattern analysis over a session log.
What this IS NOT: not a statistical MI test; no loss/threshold math.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Tuple

MODEL_ATTACK_04_VERSION = "model-attack-04.v1"

SCHEMA_PIN = "northstar.model-attack-04.v1"

#: Queries probing the same target this many times -> flag.
REPEAT_THRESHOLD = 5

#: Similarity: share this fraction of tokens to count as near-duplicate.
SIMILARITY_THRESHOLD = 0.7


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


_MI_PATTERNS = [
    r"was\s+.+\s+in\s+(your|the)\s+training",
    r"have\s+you\s+seen\s+",
    r"do\s+you\s+(remember|recognize)\s+",
    r"how\s+confident\s+are\s+you",
    r"training\s+(data|set|corpus)",
]


def _tokens(text: str) -> set:
    return set(text.lower().split())


def _similar(a: str, b: str) -> bool:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return False
    return len(ta & tb) / max(len(ta), len(tb)) >= SIMILARITY_THRESHOLD


def detect_membership_probing(queries: List[str]) -> Tuple[bool, str]:
    """Analyze a session query log. Returns (flagged, reason)."""
    if not isinstance(queries, list) or not all(
        isinstance(q, str) for q in queries
    ):
        raise ModelAttackError("queries must be a list of str")
    mi_hits = 0
    for q in queries:
        lowered = q.lower()
        if any(re.search(p, lowered) for p in _MI_PATTERNS):
            mi_hits += 1
    if mi_hits >= 2:
        return True, f"{mi_hits} explicit membership questions"
    # Near-duplicate probing of one target.
    for i, q in enumerate(queries):
        similar_count = sum(
            1 for j, other in enumerate(queries) if j != i and _similar(q, other)
        )
        if similar_count >= REPEAT_THRESHOLD:
            return True, f"near-duplicate probing x{similar_count + 1}"
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    flagged, _ = detect_membership_probing(
        ["Was alice@example.com in your training data?",
         "Have you seen alice@example.com before?"]
    )
    assert flagged is True
    base = "Tell me about the Eiffel tower height in meters please"
    flagged, _ = detect_membership_probing([base] * 7)
    assert flagged is True
    flagged, _ = detect_membership_probing(
        ["What is 2+2?", "Who wrote Hamlet?", "Capital of Peru?"]
    )
    assert flagged is False
    try:
        detect_membership_probing("not a list")  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-04 OK (mock)")


if __name__ == "__main__":
    main()
