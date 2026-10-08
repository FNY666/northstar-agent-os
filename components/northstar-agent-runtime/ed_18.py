"""Dice coefficient on character bigrams

Dice overlap of character bigrams, in [0, 1].

What this IS: Dice: 2|A&B| / (|A| + |B|) over bigram sets.

What this IS NOT:
* Jaccard -- ed_17 divides by the union instead.
* an edit distance -- alignment-free.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_18_VERSION = "ed-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-18.v1"


def _bigrams(s: str) -> set:
    return {s[i:i + 2] for i in range(len(s) - 1)}


def dice_bigram(a: str, b: str) -> float:
    """Dice coefficient of character-bigram sets."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = _bigrams(a), _bigrams(b)
    if not A and not B:
        return 1.0 if a == b else 0.0
    if not A or not B:
        return 0.0
    return 2.0 * len(A & B) / (len(A) + len(B))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    """Self-check."""
    assert dice_bigram("night", "nacht") == 0.25
    assert dice_bigram("abc", "abc") == 1.0
    assert dice_bigram("", "") == 1.0
    assert dice_bigram("a", "b") == 0.0
    assert abs(dice_bigram("abc", "abd") - 0.5) < 1e-9
    try:
        dice_bigram(2, "b")
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("18-dice-bigram OK")


if __name__ == "__main__":
    main()
