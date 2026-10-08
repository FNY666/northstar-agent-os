"""LCS of three strings (layered DP)

What this IS: three-string LCS in O(m*n*p) time but only O(n*p) space via layer rolling.

What this IS NOT:
* the full 3D table -- see lcs_13 when the table is needed.
* pairwise LCS -- see lcs_01.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_14_VERSION = "lcs-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-14.v1"


def lcs3_layered(a: str, b: str, c: str) -> int:
    # Keep two (n+1)x(p+1) layers instead of the full cube.
    m, n, p = len(a), len(b), len(c)
    prev = [[0] * (p + 1) for _ in range(n + 1)]
    for i in range(1, m + 1):
        cur = [[0] * (p + 1) for _ in range(n + 1)]
        ai = a[i - 1]
        for j in range(1, n + 1):
            bj = b[j - 1]
            for k in range(1, p + 1):
                if ai == bj == c[k - 1]:
                    cur[j][k] = prev[j - 1][k - 1] + 1
                else:
                    x, y, z = prev[j][k], cur[j - 1][k], cur[j][k - 1]
                    cur[j][k] = x if x >= y and x >= z else (y if y >= z else z)
        prev = cur
    return prev[n][p]

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
    assert lcs3_layered("abc", "abc", "abc") == 3
    assert lcs3_layered("abc", "def", "ghi") == 0
    assert lcs3_layered("abcde", "ace", "ae") == 2
    assert lcs3_layered("", "a", "b") == 0
    assert lcs3_layered("abcd", "abce", "abcf") == 3
    assert stdlib_only()
    print("14-ok OK")


if __name__ == "__main__":
    main()
