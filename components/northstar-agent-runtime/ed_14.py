"""Sellers approximate substring search

Minimum edit distance between the pattern and any substring of the text.

What this IS: Sellers' algorithm: the pattern may start matching at any text offset for free.

What this IS NOT:
* full-string Levenshtein -- leading text is skipped at zero cost.
* a boolean search -- this returns the minimum distance.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_14_VERSION = "ed-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-14.v1"


def sellers(pattern: str, text: str) -> int:
    """Min edit distance between pattern and any substring of text."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        raise TypeError("inputs must be str")
    m, n = len(pattern), len(text)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        pi = pattern[i - 1]
        for j in range(1, n + 1):
            cost = 0 if pi == text[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return min(prev)

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
    assert sellers("abc", "xxabcxx") == 0
    assert sellers("abd", "xxabcxx") == 1
    assert sellers("", "abc") == 0
    assert sellers("abc", "") == 3
    try:
        sellers("a", 7)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("14-sellers OK")


if __name__ == "__main__":
    main()
