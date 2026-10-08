"""Normalized Levenshtein distance

Levenshtein divided by the longer string length, in [0, 1].

What this IS: d(a,b)/max(len(a),len(b)); 0.0 for two empty strings.

What this IS NOT:
* a raw count -- ed_01 returns the unnormalized integer.
* a similarity -- 0.0 means identical here.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_10_VERSION = "ed-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-10.v1"


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


def normalized_levenshtein(a: str, b: str) -> float:
    """Levenshtein / max(len(a), len(b)); 0.0 when both are empty."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not a and not b:
        return 0.0
    return _lev(a, b) / max(len(a), len(b))

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
    assert abs(normalized_levenshtein("kitten", "sitting") - 3 / 7) < 1e-9
    assert normalized_levenshtein("", "") == 0.0
    assert normalized_levenshtein("abc", "abc") == 0.0
    assert normalized_levenshtein("", "abc") == 1.0
    assert 0.0 <= normalized_levenshtein("abc", "xyz") <= 1.0
    try:
        normalized_levenshtein("a", b"a")
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("10-normalized OK")


if __name__ == "__main__":
    main()
