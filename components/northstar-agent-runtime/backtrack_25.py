"""Backtracking: matchsticks to square - can they form a square?

IS: decides whether all matchsticks can be arranged into a square, i.e.
partitioned into 4 non-empty groups of equal sum, via descending-order
side backtracking with duplicate-side pruning. IS NOT: a geometry
solver - it checks sums only, never angles, crossings, or physical
placability of the sticks.
"""

import ast
from typing import List, Optional

VERSION = "backtrack_25.v1"


def can_form_square(matchsticks: List[int]) -> bool:
    """True iff the sticks can form a square (4 equal-sum sides)."""
    if not matchsticks:
        return False
    total = sum(matchsticks)
    if total % 4 != 0:
        return False
    side = total // 4
    sticks = sorted(matchsticks, reverse=True)
    if sticks[0] > side:
        return False
    sides = [0] * 4

    def dfs(i: int) -> bool:
        if i == len(sticks):
            return all(s == side for s in sides)
        v = sticks[i]
        seen = set()
        for j in range(4):
            if sides[j] + v > side or sides[j] in seen:
                continue
            seen.add(sides[j])
            sides[j] += v
            if dfs(i + 1):
                return True
            sides[j] -= v
        return False

    return dfs(0)


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert can_form_square([1, 1, 2, 2, 2]) is True
    assert can_form_square([3, 3, 3, 3, 4]) is False
    assert can_form_square([5, 5, 5, 5, 4, 4, 4, 4, 3, 3, 3, 3]) is True
    assert can_form_square([]) is False
    assert can_form_square([1, 2, 3]) is False
    print("backtrack_25 OK")


if __name__ == "__main__":
    main()
