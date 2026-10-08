"""LCS with wildcard

What this IS: LCS where '?' (configurable) matches any single character.

What this IS NOT:
* plain LCS -- see lcs_01.
* regex matching -- wildcards here are single-char only.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_22_VERSION = "lcs-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-22.v1"


def lcs_wild(a: str, b: str, wild: str = "?") -> int:
    # '?' on either side matches any character.
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            bj = b[j - 1]
            if ai == bj or ai == wild or bj == wild:
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
    assert lcs_wild("a?c", "abc") == 3
    assert lcs_wild("???", "abc") == 3
    assert lcs_wild("a?b", "axc") == 2
    assert lcs_wild("?", "") == 0
    assert lcs_wild("abc", "abc") == 3
    assert stdlib_only()
    print("22-ok OK")


if __name__ == "__main__":
    main()
