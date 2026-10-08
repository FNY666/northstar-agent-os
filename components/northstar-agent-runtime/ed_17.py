"""Jaccard similarity on character bigrams

Set overlap of character bigrams, in [0, 1].

What this IS: Jaccard over bigram sets: |A&B| / |A|B|.

What this IS NOT:
* edit distance -- no alignment is computed.
* Dice -- ed_18 uses the 2|A&B|/(|A|+|B|) form.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_17_VERSION = "ed-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-17.v1"


def _bigrams(s: str) -> set:
    return {s[i:i + 2] for i in range(len(s) - 1)}


def jaccard_bigram(a: str, b: str) -> float:
    """Jaccard similarity of character-bigram sets."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = _bigrams(a), _bigrams(b)
    if not A and not B:
        return 1.0 if a == b else 0.0
    if not A or not B:
        return 0.0
    return len(A & B) / len(A | B)

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
    assert abs(jaccard_bigram("night", "nacht") - 1 / 7) < 1e-9
    assert jaccard_bigram("abc", "abc") == 1.0
    assert jaccard_bigram("", "") == 1.0
    assert jaccard_bigram("a", "b") == 0.0
    assert jaccard_bigram("abc", "abd") == 1 / 3
    try:
        jaccard_bigram("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("17-jaccard-bigram OK")


if __name__ == "__main__":
    main()
