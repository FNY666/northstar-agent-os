"""Model attack 20: attention manipulation detection (MOCK), Simulated.

Detects prompt structures designed to hijack model attention: the
same anchor phrase repeated to dominate salience, "IMPORTANT:"-style
priority markers stacked on attacker content, and recency-buried
instructions that exploit positional bias.

This is a MOCK: true attention analysis needs model internals. The
structural heuristics here catch the prompt-engineering signature
at the input boundary.

What this IS: structural attention-hijack heuristics.
What this IS NOT: not attention-weight analysis.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from typing import Tuple

MODEL_ATTACK_20_VERSION = "model-attack-20.v1"

SCHEMA_PIN = "northstar.model-attack-20.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


_PRIORITY_MARKERS = [
    r"\bimportant\b",
    r"\bcritical\b",
    r"\burgent\b",
    r"\bpriority\b",
    r"!!!+",
    r"\bnote\s+well\b",
]

#: Same anchor phrase repeated this many times -> flag.
ANCHOR_REPEAT = 4

#: Priority markers this many -> flag.
MARKER_THRESHOLD = 4


def detect_attention_manipulation(text: str) -> Tuple[bool, str]:
    """Return (flagged, reason). Fail-closed on non-str."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    lowered = text.lower()
    words = lowered.split()
    # Buried instruction first: most specific signal (positional exploit).
    if len(words) > 120:
        tail = " ".join(words[-60:])
        if re.search(r"\b(ignore|disregard|forget|override)\b", tail):
            return True, "imperative buried in input tail"
    markers = 0
    for pat in _PRIORITY_MARKERS:
        markers += len(re.findall(pat, lowered))
    if markers >= MARKER_THRESHOLD:
        return True, f"priority-marker stacking x{markers}"
    # Anchor repetition: same 3+-word phrase repeated.
    phrases = [" ".join(words[i:i + 3]) for i in range(len(words) - 2)]
    counts = Counter(phrases)
    for phrase, n in counts.most_common(3):
        if n >= ANCHOR_REPEAT and len(set(phrase.split())) > 1:
            return True, f"anchor-phrase repetition x{n}: {phrase[:30]!r}"
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "pathlib", "re", "typing"}
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
    flagged, _ = detect_attention_manipulation(
        "do the thing do the thing do the thing do the thing now"
    )
    assert flagged is True
    flagged, _ = detect_attention_manipulation(
        "IMPORTANT critical urgent priority!!! read this important note"
    )
    assert flagged is True
    flagged, _ = detect_attention_manipulation(
        "Please write a short summary of the attached document."
    )
    assert flagged is False
    try:
        detect_attention_manipulation(0)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-20 OK (mock)")


if __name__ == "__main__":
    main()
