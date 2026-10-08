"""Needleman-Wunsch global alignment

Optimal global alignment score with linear gap penalty.

What this IS: the Needleman-Wunsch score: match/mismatch/gap summed over the full alignment.

What this IS NOT:
* an edit distance -- higher is better here.
* affine gaps -- ed_09/ed_38 separate gap open from extend.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_15_VERSION = "ed-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-15.v1"


def needleman_wunsch(
    a: str,
    b: str,
    match: int = 1,
    mismatch: int = -1,
    gap: int = -1,
) -> int:
    """Needleman-Wunsch global alignment score."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = [j * gap for j in range(n + 1)]
    for i in range(1, m + 1):
        cur = [i * gap] + [0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            s = match if ai == b[j - 1] else mismatch
            cur[j] = max(prev[j] + gap, cur[j - 1] + gap, prev[j - 1] + s)
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
    assert needleman_wunsch("A", "A") == 1
    assert needleman_wunsch("A", "") == -1
    assert needleman_wunsch("A", "C") == -1
    assert needleman_wunsch("AC", "AC") == 2
    assert needleman_wunsch("", "") == 0
    try:
        needleman_wunsch("A", 2)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("15-needleman-wunsch OK")


if __name__ == "__main__":
    main()
