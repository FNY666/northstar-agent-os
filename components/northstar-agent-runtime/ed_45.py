"""Threshold decision (within distance k)

Boolean check: is the edit distance at most k?

What this IS: a fail-fast boolean using bounded two-row DP.

What this IS NOT:
* the distance value -- ed_12 returns k+1 when over budget.
* an approximation -- exact up to the threshold.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_45_VERSION = "ed-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-45.v1"


def within_distance(a: str, b: str, k: int) -> bool:
    """True iff Levenshtein(a, b) <= k (early exit)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    m, n = len(a), len(b)
    if abs(m - n) > k:
        return False
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        row_min = i
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if cur[j] < row_min:
                row_min = cur[j]
        if row_min > k:
            return False
        prev = cur
    return prev[n] <= k

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
    assert within_distance("kitten", "sitting", 3) is True
    assert within_distance("kitten", "sitting", 2) is False
    assert within_distance("abc", "abc", 0) is True
    assert within_distance("", "abc", 2) is False
    try:
        within_distance("a", "b", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("45-within OK")


if __name__ == "__main__":
    main()
