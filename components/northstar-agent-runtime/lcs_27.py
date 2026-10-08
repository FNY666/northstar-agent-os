"""LCS with custom equality

What this IS: LCS length where character match is decided by a caller-supplied predicate.

What this IS NOT:
* plain equality -- see lcs_01.
* wildcard matching -- see lcs_22.
"""

from __future__ import annotations

import ast
from typing import Callable
#: Module version.
LCS_27_VERSION = "lcs-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-27.v1"


def lcs_pred(a: str, b: str, eq: Callable[[str, str], bool]) -> int:
    # DP identical to lcs_01 except the match test is pluggable.
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if eq(ai, b[j - 1]):
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[n]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "typing"}
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
    assert lcs_pred("abcde", "ace", lambda x, y: x == y) == 3
    assert lcs_pred("AbC", "abc", lambda x, y: x.lower() == y.lower()) == 3
    assert lcs_pred("abc", "def", lambda x, y: x == y) == 0
    assert lcs_pred([1, 2, 3, 4], [2, 4, 6], lambda x, y: x % 2 == y % 2) == 2
    assert lcs_pred("", "a", lambda x, y: True) == 0
    assert stdlib_only()
    print("27-ok OK")


if __name__ == "__main__":
    main()
