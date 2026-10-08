"""Smith-Waterman local alignment

Best local alignment score; never negative (floor at 0).

What this IS: Smith-Waterman: the maximum scoring local region, 0 if nothing aligns.

What this IS NOT:
* global alignment -- ed_15 forces end-to-end alignment.
* a distance -- higher means more similar.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_16_VERSION = "ed-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-16.v1"


def smith_waterman(
    a: str,
    b: str,
    match: int = 2,
    mismatch: int = -1,
    gap: int = -1,
) -> int:
    """Smith-Waterman maximum local alignment score (>= 0)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    best = 0
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            s = match if ai == b[j - 1] else mismatch
            cur[j] = max(0, prev[j] + gap, cur[j - 1] + gap, prev[j - 1] + s)
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
    assert smith_waterman("AC", "AC") == 4
    assert smith_waterman("AAAA", "TTTT") == 0
    assert smith_waterman("", "AC") == 0
    assert smith_waterman("GGTTGACTA", "TGTTACGG") >= 4
    try:
        smith_waterman("A", None)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("16-smith-waterman OK")


if __name__ == "__main__":
    main()
