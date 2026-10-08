"""Memoized Box Stacking: memoization example.

Tallest stack with strictly smaller base: generate all rotations (w <= d), sort, then LIS-style DP over an index cache.

What this IS: a real memoized box-stacking height solver generating all 3 rotations.
What this IS NOT: a stability simulation; the host picks the physics.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_42_VERSION = "memo-box-stacking.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-box-stacking.v1"


class MemoError(Exception):
    """Fail-closed."""


def box_stack(boxes: tuple, _cache: dict | None = None) -> int:
    """Memoized max stack height."""
    cache: dict = _cache if _cache is not None else {}
    rots = []
    for (w, d, h) in boxes:
        for (a, b, c) in ((w, d, h), (w, h, d), (d, h, w)):
            rots.append((min(a, b), max(a, b), c))
    rots = tuple(sorted(set(rots)))
    n = len(rots)

    def dp(i: int) -> int:
        if i in cache:
            return cache[i]
        best = rots[i][2]
        for k in range(i):
            if rots[k][0] < rots[i][0] and rots[k][1] < rots[i][1]:
                best = max(best, dp(k) + rots[i][2])
        cache[i] = best
        return best

    return max((dp(i) for i in range(n)), default=0)

def test_box_stack_example():
    assert box_stack(((4, 6, 7), (1, 2, 3), (4, 5, 6), (10, 12, 32))) == 60


def test_box_stack_single():
    # Rotations let (1,2,3) stack as (2,3,1) base + (1,2,3) on top: 1 + 3 = 4.
    assert box_stack(((1, 2, 3),)) == 4


def test_box_stack_empty():
    assert box_stack(()) == 0

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_box_stack_example()
    test_box_stack_single()
    test_box_stack_empty()
    assert stdlib_only()
    print("memo-42 OK: box-stacking")


if __name__ == "__main__":
    main()
