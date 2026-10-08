"""Pairwise LCS matrix

What this IS: all-pairs LCS length matrix for a list of strings.

What this IS NOT:
* single-pair LCS -- see lcs_01.
* similarity ratios -- see lcs_17.
"""

from __future__ import annotations

import ast
from typing import List, Sequence
#: Module version.
LCS_50_VERSION = "lcs-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-50.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def lcs_pairwise(strs: Sequence[str]) -> List[List[int]]:
    # Symmetric matrix; diagonal holds the string lengths.
    k = len(strs)
    mat = [[0] * k for _ in range(k)]
    for i in range(k):
        for j in range(i, k):
            v = _lcs_len(strs[i], strs[j])
            mat[i][j] = v
            mat[j][i] = v
    return mat

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
    assert lcs_pairwise(["abc", "abd", "xyz"]) == [[3, 2, 0], [2, 3, 0], [0, 0, 3]]
    assert lcs_pairwise(["", "a"]) == [[0, 0], [0, 1]]
    assert lcs_pairwise(["ab"]) == [[2]]
    assert lcs_pairwise([]) == []
    m = lcs_pairwise(["abcde", "ace"])
    assert m[0][1] == m[1][0] == 3
    assert stdlib_only()
    print("50-ok OK")


if __name__ == "__main__":
    main()
