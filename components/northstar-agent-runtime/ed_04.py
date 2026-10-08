"""Indel distance (insert/delete only)

Edit distance allowing only insertions and deletions.

What this IS: len(a)+len(b)-2*LCS(a,b): no substitutions, so abc->def costs 6.

What this IS NOT:
* Levenshtein -- substitutions are forbidden here.
* a similarity score -- this returns an integer distance.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_04_VERSION = "ed-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-04.v1"


def indel_distance(a: str, b: str) -> int:
    """Insert/delete-only distance = m + n - 2*LCS(a, b)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return m + n - 2 * prev[n]

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
    assert indel_distance("abc", "abc") == 0
    assert indel_distance("abc", "def") == 6
    assert indel_distance("kitten", "sitting") == 5
    assert indel_distance("", "abc") == 3
    try:
        indel_distance(1, "abc")
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("04-indel OK")


if __name__ == "__main__":
    main()
