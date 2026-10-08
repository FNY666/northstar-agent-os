"""Longest common subarray

What this IS: longest contiguous run common to two sequences (works on any sequence).

What this IS NOT:
* longest common substring -- see lcs_05 (string version).
* non-contiguous LCS -- see lcs_19.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_40_VERSION = "lcs-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-40.v1"


def lcsubarray(a, b) -> int:
    # Contiguous DP: extend runs, track the best.
    n = len(b)
    prev = [0] * (n + 1)
    best = 0
    for x in a:
        cur = [0] * (n + 1)
        for j in range(1, n + 1):
            if x == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
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
    assert lcsubarray([1, 2, 3, 2, 1], [3, 2, 1, 4, 7]) == 3
    assert lcsubarray([0, 0, 0], [0, 0]) == 2
    assert lcsubarray([1], [2]) == 0
    assert lcsubarray([], [1]) == 0
    assert lcsubarray("abcde", "abfce") == 2
    assert stdlib_only()
    print("40-ok OK")


if __name__ == "__main__":
    main()
