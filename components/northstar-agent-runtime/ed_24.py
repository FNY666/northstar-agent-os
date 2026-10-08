"""Prefix edit distance

Minimum Levenshtein between a and any prefix of b.

What this IS: min over prefixes of b of lev(a, prefix); b's tail is free.

What this IS NOT:
* Sellers -- ed_14 allows the match to start anywhere in the text.
* symmetric -- only b's prefixes are free.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_24_VERSION = "ed-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-24.v1"


def prefix_edit_distance(a: str, b: str) -> int:
    """Minimum Levenshtein distance between a and any prefix of b."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    best = m  # distance to the empty prefix
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        if n >= 1:
            row_best = min(cur[1:])
            if row_best < best:
                best = row_best
        prev = cur
    return best

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
    assert prefix_edit_distance("abc", "abcdef") == 0
    assert prefix_edit_distance("abc", "xabc") == 1
    assert prefix_edit_distance("", "abc") == 0
    assert prefix_edit_distance("abc", "") == 3
    assert prefix_edit_distance("abc", "abc") == 0
    try:
        prefix_edit_distance("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("24-prefix OK")


if __name__ == "__main__":
    main()
