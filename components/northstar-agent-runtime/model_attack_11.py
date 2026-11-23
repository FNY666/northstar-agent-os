"""Model attack 11: distillation attack detection, Simulated.

Detects queries designed to harvest soft labels for distilling a
student model: requests for full probability distributions, logits,
top-k scores across many inputs, and temperature/confidence
calibration probing.

What this IS: API-side soft-label harvesting detection.
What this IS NOT: cannot distinguish legitimate evaluation use;
host allowlists eval traffic.
"""

from __future__ import annotations

import ast
import re
from typing import List, Tuple

MODEL_ATTACK_11_VERSION = "model-attack-11.v1"

SCHEMA_PIN = "northstar.model-attack-11.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


_DISTILL_PATTERNS = [
    r"probabilit(y|ies)",
    r"logits?",
    r"top[-\s]?k",
    r"confidence\s+(scores?|for\s+each)",
    r"distribution\s+over",
    r"softmax",
    r"temperature",
    r"all\s+classes",
]

#: How many soft-label requests in a session trigger the flag.
SESSION_THRESHOLD = 4


def detect_distillation_query(text: str) -> Tuple[bool, str]:
    """Single-query check. Returns (flagged, reason)."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    lowered = text.lower()
    for pat in _DISTILL_PATTERNS:
        m = re.search(pat, lowered)
        if m:
            return True, f"soft-label request: {m.group(0)!r}"
    return False, "clean"


def detect_distillation_session(queries: List[str]) -> Tuple[bool, str]:
    """Session-level check. Returns (flagged, reason)."""
    if not isinstance(queries, list) or not all(
        isinstance(q, str) for q in queries
    ):
        raise ModelAttackError("queries must be a list of str")
    hits = sum(1 for q in queries if detect_distillation_query(q)[0])
    if hits >= SESSION_THRESHOLD:
        return True, f"{hits} soft-label requests in session"
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
    flagged, _ = detect_distillation_query(
        "Give me the full probability distribution over all classes"
    )
    assert flagged is True
    flagged, _ = detect_distillation_query("What is the capital of France?")
    assert flagged is False
    flagged, _ = detect_distillation_session(
        [f"Return top-k logits for input {i}" for i in range(5)]
    )
    assert flagged is True
    try:
        detect_distillation_query(None)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-11 OK")


if __name__ == "__main__":
    main()
