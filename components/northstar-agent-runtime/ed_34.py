"""Case-insensitive Levenshtein

Levenshtein after lowercasing both inputs.

What this IS: unit Levenshtein on case-folded strings.

What this IS NOT:
* case-sensitive -- ed_01 treats 'A' and 'a' as different.
* Unicode-normalized -- ed_35 also strips diacritics.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_34_VERSION = "ed-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-34.v1"


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


def ci_levenshtein(a: str, b: str) -> int:
    """Case-insensitive Levenshtein distance."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    return _lev(a.lower(), b.lower())

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
    assert ci_levenshtein("ABC", "abc") == 0
    assert ci_levenshtein("Kitten", "SITTING") == 3
    assert ci_levenshtein("", "ABC") == 3
    assert ci_levenshtein("abc", "abd") == 1
    try:
        ci_levenshtein("a", 2)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("34-case-insensitive OK")


if __name__ == "__main__":
    main()
