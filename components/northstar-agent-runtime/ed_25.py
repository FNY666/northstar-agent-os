"""Ukkonen banded edit distance

Banded DP that only computes a diagonal strip of width 2k+1.

What this IS: Ukkonen's banded algorithm; returns None when the distance exceeds k.

What this IS NOT:
* the full DP -- cells outside the band are never computed.
* ed_12 -- that returns k+1 instead of None when over budget.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_25_VERSION = "ed-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-25.v1"


def ukkonen(a: str, b: str, k: int):
    """Banded edit distance; None when the distance exceeds k."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    m, n = len(a), len(b)
    if abs(m - n) > k:
        return None
    inf = k + 1
    prev = [inf] * (n + 1)
    for j in range(0, min(n, k) + 1):
        prev[j] = j
    for i in range(1, m + 1):
        cur = [inf] * (n + 1)
        lo = max(1, i - k)
        hi = min(n, i + k)
        if i <= k:
            cur[0] = i
        ai = a[i - 1]
        for j in range(lo, hi + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    d = prev[n]
    return d if d <= k else None

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
    assert ukkonen("kitten", "sitting", 3) == 3
    assert ukkonen("kitten", "sitting", 2) is None
    assert ukkonen("abc", "abc", 0) == 0
    assert ukkonen("abc", "abcdef", 2) is None
    try:
        ukkonen("a", "b", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("25-ukkonen OK")


if __name__ == "__main__":
    main()
