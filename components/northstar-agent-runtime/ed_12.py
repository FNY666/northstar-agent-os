"""Bounded Levenshtein (thresholded)

Levenshtein that bails out early when the distance exceeds k.

What this IS: exact when the distance is <= k; returns k+1 otherwise (fail-fast).

What this IS NOT:
* the full computation -- ed_01 always finishes the matrix.
* a boolean -- ed_45 answers the <= k question directly.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_12_VERSION = "ed-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-12.v1"


def levenshtein_bounded(a: str, b: str, k: int) -> int:
    """Levenshtein distance if <= k, else k + 1 (early exit)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    m, n = len(a), len(b)
    if abs(m - n) > k:
        return k + 1
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
            return k + 1
        prev = cur
    return prev[n] if prev[n] <= k else k + 1

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
    assert levenshtein_bounded("kitten", "sitting", 3) == 3
    assert levenshtein_bounded("kitten", "sitting", 2) == 3
    assert levenshtein_bounded("abc", "abc", 0) == 0
    assert levenshtein_bounded("abc", "xyz", 1) == 2
    try:
        levenshtein_bounded("a", "b", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("12-bounded OK")


if __name__ == "__main__":
    main()
