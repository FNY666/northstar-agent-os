"""Memoized Cherry Pickup: memoization example.

Two synchronized walkers from (0,0) to (n-1,n-1): state (r1, c1, r2) with c2 derived from the step count. Thorns (-1) are fail-closed to negative infinity.

What this IS: a real memoized two-walker cherry maximizer, floored at 0.
What this IS NOT: a single-path solver; the host picks the problem.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_46_VERSION = "memo-cherry-pickup.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-cherry-pickup.v1"


class MemoError(Exception):
    """Fail-closed."""


def cherry_pickup(grid: tuple, _cache: dict | None = None) -> int:
    """Memoized cherry-pickup max cherries."""
    cache: dict = _cache if _cache is not None else {}
    n = len(grid)

    def dp(r1: int, c1: int, r2: int) -> float:
        c2 = r1 + c1 - r2
        key = (r1, c1, r2)
        if key in cache:
            return cache[key]
        if not (0 <= r1 < n and 0 <= c1 < n and 0 <= r2 < n and 0 <= c2 < n):
            cache[key] = float("-inf")
        elif grid[r1][c1] == -1 or grid[r2][c2] == -1:
            cache[key] = float("-inf")
        elif r1 == n - 1 and c1 == n - 1:
            cache[key] = grid[r1][c1]
        else:
            val = grid[r1][c1]
            if (r1, c1) != (r2, c2):
                val += grid[r2][c2]
            best = max(
                dp(r1 + 1, c1, r2),
                dp(r1 + 1, c1, r2 + 1),
                dp(r1, c1 + 1, r2),
                dp(r1, c1 + 1, r2 + 1),
            )
            cache[key] = val + best
        return cache[key]

    return max(dp(0, 0, 0), 0)

def test_cherry_pickup_example():
    assert cherry_pickup(((0, 1, -1), (1, 0, -1), (1, 1, 1))) == 5


def test_cherry_pickup_single():
    assert cherry_pickup(((1,),)) == 1


def test_cherry_pickup_blocked():
    assert cherry_pickup(((-1,),)) == 0

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
    test_cherry_pickup_example()
    test_cherry_pickup_single()
    test_cherry_pickup_blocked()
    assert stdlib_only()
    print("memo-46 OK: cherry-pickup")


if __name__ == "__main__":
    main()
