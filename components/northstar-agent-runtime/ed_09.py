"""Affine-gap global alignment score

Needleman-Wunsch-style score with separate gap open/extend penalties.

What this IS: Gotoh's three-matrix affine-gap alignment with fixed scoring.

What this IS NOT:
* unit-cost edit distance -- gaps cost open + extend here.
* local alignment -- ed_16 finds the best local region.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_09_VERSION = "ed-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-09.v1"


def affine_align(
    a: str,
    b: str,
    match: float = 2.0,
    mismatch: float = -1.0,
    gap_open: float = -2.0,
    gap_extend: float = -0.5,
) -> float:
    """Affine-gap global alignment score (Gotoh)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    neg = float("-inf")
    M = [[neg] * (n + 1) for _ in range(m + 1)]
    X = [[neg] * (n + 1) for _ in range(m + 1)]
    Y = [[neg] * (n + 1) for _ in range(m + 1)]
    M[0][0] = 0.0
    for i in range(1, m + 1):
        X[i][0] = gap_open + (i - 1) * gap_extend
        M[i][0] = X[i][0]
    for j in range(1, n + 1):
        Y[0][j] = gap_open + (j - 1) * gap_extend
        M[0][j] = Y[0][j]
    for i in range(1, m + 1):
        ai = a[i - 1]
        for j in range(1, n + 1):
            s = match if ai == b[j - 1] else mismatch
            X[i][j] = max(M[i - 1][j] + gap_open, X[i - 1][j] + gap_extend)
            Y[i][j] = max(M[i][j - 1] + gap_open, Y[i][j - 1] + gap_extend)
            M[i][j] = max(M[i - 1][j - 1] + s, X[i][j], Y[i][j])
    return M[m][n]

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
    assert affine_align("A", "A") == 2.0
    assert affine_align("A", "C") == -1.0
    assert affine_align("AA", "AA") == 4.0
    assert affine_align("", "") == 0.0
    assert affine_align("ACGT", "ACGT") == 8.0
    try:
        affine_align("A", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("09-affine OK")


if __name__ == "__main__":
    main()
