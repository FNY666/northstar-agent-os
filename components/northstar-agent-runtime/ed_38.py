"""Parametric affine-gap alignment

Gotoh affine-gap alignment with all four scores caller-supplied.

What this IS: ed_09 generalized: match/mismatch/gap_open/gap_extend are parameters.

What this IS NOT:
* fixed scoring -- ed_09 pins the four scores.
* local -- this aligns end to end.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_38_VERSION = "ed-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-38.v1"


def affine_align_params(
    a: str,
    b: str,
    match: float,
    mismatch: float,
    gap_open: float,
    gap_extend: float,
) -> float:
    """Affine-gap global alignment with caller-supplied scores."""
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
    assert affine_align_params("A", "A", 2.0, -1.0, -2.0, -0.5) == 2.0
    assert affine_align_params("AA", "AA", 2.0, -1.0, -2.0, -0.5) == 4.0
    assert affine_align_params("", "", 1.0, -1.0, -1.0, -1.0) == 0.0
    assert affine_align_params("A", "C", 1.0, -3.0, -1.0, -1.0) == -2.0
    try:
        affine_align_params("A", 1, 1.0, -1.0, -1.0, -1.0)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("38-affine-params OK")


if __name__ == "__main__":
    main()
