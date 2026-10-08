"""Word-level Levenshtein distance

Levenshtein computed over whitespace-separated tokens, not characters.

What this IS: token-level edit distance: insert/delete/substitute whole words.

What this IS NOT:
* character Levenshtein -- ed_01 works per character.
* transposition aware -- ed_49 adds word swaps.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_20_VERSION = "ed-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-20.v1"


def word_levenshtein(a: str, b: str) -> int:
    """Levenshtein distance over whitespace-separated words."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A, B = a.split(), b.split()
    m, n = len(A), len(B)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if A[i - 1] == B[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]

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
    assert word_levenshtein("hello world", "hello there") == 1
    assert word_levenshtein("a b c", "a b c") == 0
    assert word_levenshtein("", "a b") == 2
    assert word_levenshtein("the cat sat", "the dog sat") == 1
    try:
        word_levenshtein("a", ["a"])
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("20-word-level OK")


if __name__ == "__main__":
    main()
