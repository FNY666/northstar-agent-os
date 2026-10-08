"""Bigram-sequence edit distance

Levenshtein over the sequence of character bigrams.

What this IS: tokenizes each string into overlapping bigrams, then unit Levenshtein.

What this IS NOT:
* set-based bigram measures -- order matters here.
* word-level -- ed_20 tokenizes on whitespace instead.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_31_VERSION = "ed-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-31.v1"


def _seq_lev(A: List[str], B: List[str]) -> int:
    m, n = len(A), len(B)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if A[i - 1] == B[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def bigram_sequence_distance(a: str, b: str) -> int:
    """Levenshtein distance over overlapping-bigram sequences."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    A = [a[i:i + 2] for i in range(len(a) - 1)]
    B = [b[i:i + 2] for i in range(len(b) - 1)]
    return _seq_lev(A, B)

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
    assert bigram_sequence_distance("abc", "abc") == 0
    assert bigram_sequence_distance("abcd", "abce") == 1
    assert bigram_sequence_distance("", "") == 0
    assert bigram_sequence_distance("ab", "ba") == 1
    try:
        bigram_sequence_distance("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("31-bigram-seq OK")


if __name__ == "__main__":
    main()
