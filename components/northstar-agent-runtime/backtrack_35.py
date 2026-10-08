"""Backtracking: Nonogram row solver (mock).

IS: enumerates every valid 0/1 pattern of a single row of given length
    that realises the block clues (e.g. clues [3, 1] means a block of 3
    then a block of 1, separated by >= 1 zero).
IS NOT: a full Nonogram grid solver; it handles one row only and does no
    column interaction or line-solving propagation.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

VERSION = "backtrack_35.v1"


def row_patterns(length: int, clues: List[int]) -> List[Tuple[int, ...]]:
    """All binary row patterns of ``length`` matching ``clues``."""
    if length < 0:
        raise ValueError("length must be >= 0")
    if any(c <= 0 for c in clues):
        raise ValueError("clues must be positive")
    if sum(clues) + max(len(clues) - 1, 0) > length:
        return []

    out: List[Tuple[int, ...]] = []

    def rec(pos: int, ci: int, cur: List[int]) -> None:
        if ci == len(clues):
            out.append(tuple(cur + [0] * (length - pos)))
            return
        block = clues[ci]
        # minimum cells the remaining blocks (with gaps) still need
        rest = sum(clues[ci + 1:]) + len(clues[ci + 1:])
        for start in range(pos, length - block - rest + 1):
            new = cur + [0] * (start - pos) + [1] * block
            if ci < len(clues) - 1:
                rec(start + block + 1, ci + 1, new + [0])
            else:
                rec(start + block, ci + 1, new)

    rec(0, 0, [])
    return out


def pattern_clues(pattern: Tuple[int, ...]) -> List[int]:
    """Block clues realised by a 0/1 pattern (helper for tests)."""
    clues: List[int] = []
    run = 0
    for v in pattern:
        if v:
            run += 1
        elif run:
            clues.append(run)
            run = 0
    if run:
        clues.append(run)
    return clues


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import is allowed."""
    allowed = {"__future__", "ast", "typing"}
    with open(__file__) as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    # clues [3] in length 5 -> 3 placements
    pats = row_patterns(5, [3])
    assert len(pats) == 3, pats
    assert all(len(p) == 5 and pattern_clues(p) == [3] for p in pats)
    # empty clues -> single all-zero row
    assert row_patterns(4, []) == [(0, 0, 0, 0)]
    # clues [1,1] in length 5 -> C(4,2) = 6 placements
    pats2 = row_patterns(5, [1, 1])
    assert len(pats2) == 6, pats2
    assert all(pattern_clues(p) == [1, 1] for p in pats2)
    # impossible clues -> no patterns
    assert row_patterns(3, [2, 2]) == []
    assert row_patterns(0, [1]) == []
    # bad input
    try:
        row_patterns(5, [0])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-positive clue")
    assert stdlib_only()
    print("backtrack_35 OK")


if __name__ == "__main__":
    main()
