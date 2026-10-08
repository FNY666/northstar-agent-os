"""Reversal-symmetry check

Levenshtein verified against the reversed-string computation.

What this IS: lev(a,b) with an internal assert that lev(reverse(a),reverse(b)) matches.

What this IS NOT:
* a new metric -- the value equals ed_01 exactly.
* a proof -- it re-checks the symmetry property at runtime.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_36_VERSION = "ed-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-36.v1"


def _lev(a: str, b: str) -> int:
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def symmetric_levenshtein(a: str, b: str) -> int:
    """Levenshtein distance, cross-checked on reversed inputs."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    d1 = _lev(a, b)
    d2 = _lev(a[::-1], b[::-1])
    if d1 != d2:
        raise AssertionError("reversal symmetry violated")
    return d1

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
    assert symmetric_levenshtein("kitten", "sitting") == 3
    assert symmetric_levenshtein("", "abc") == 3
    assert symmetric_levenshtein("abc", "abc") == 0
    assert symmetric_levenshtein("abcd", "dcba") == 4
    try:
        symmetric_levenshtein("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("36-symmetry OK")


if __name__ == "__main__":
    main()
