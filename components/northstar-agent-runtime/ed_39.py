"""Overlap (semi-global) alignment score

Global in the pattern, free end gaps in the text.

What this IS: semi-global alignment: the pattern must align fully, text ends are free.

What this IS NOT:
* fully global -- ed_15 penalizes text overhang.
* local -- ed_16 can also clip the pattern.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_39_VERSION = "ed-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-39.v1"


def overlap_alignment(
    pattern: str,
    text: str,
    match: int = 2,
    mismatch: int = -1,
    gap: int = -2,
) -> int:
    """Semi-global alignment score (free end gaps in text)."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        raise TypeError("inputs must be str")
    m, n = len(pattern), len(text)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [i * gap] + [0] * n
        pi = pattern[i - 1]
        for j in range(1, n + 1):
            s = match if pi == text[j - 1] else mismatch
            cur[j] = max(prev[j] + gap, cur[j - 1] + gap, prev[j - 1] + s)
        prev = cur
    return max(prev)

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
    assert overlap_alignment("abc", "xxabcxx") == 6
    assert overlap_alignment("abc", "abc") == 6
    assert overlap_alignment("", "abc") == 0
    assert overlap_alignment("abc", "") == -6
    try:
        overlap_alignment("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("39-overlap OK")


if __name__ == "__main__":
    main()
