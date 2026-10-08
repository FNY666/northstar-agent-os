"""Memoized Min Cost Climbing Stairs: memoization example.

Cheapest cost to the top: cost(i) + min(cost(i+1), cost(i+2)), starting from step 0 or 1. The index cache gives O(n).

What this IS: a real memoized min-cost climber over an index cache.
What this IS NOT: a path-reconstruction routine; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_16_VERSION = "memo-min-cost-climbing.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-min-cost-climbing.v1"


class MemoError(Exception):
    """Fail-closed."""


def min_cost(cost: tuple, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized cost from step i to the top."""
    cache: dict = _cache if _cache is not None else {}
    if i in cache:
        return cache[i]
    if i >= len(cost):
        cache[i] = 0
    else:
        cache[i] = cost[i] + min(min_cost(cost, i + 1, cache), min_cost(cost, i + 2, cache))
    return cache[i]


def cheapest(cost: tuple) -> int:
    """Cheapest cost starting from step 0 or 1."""
    cache: dict = {}
    return min(min_cost(cost, 0, cache), min_cost(cost, 1, cache))

def test_cheapest_example():
    assert cheapest((10, 15, 20)) == 15


def test_cheapest_long():
    assert cheapest((1, 100, 1, 1, 1, 100, 1, 1, 100, 1)) == 6


def test_cheapest_empty():
    assert cheapest(()) == 0

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
    test_cheapest_example()
    test_cheapest_long()
    test_cheapest_empty()
    assert stdlib_only()
    print("memo-16 OK: min-cost-climbing")


if __name__ == "__main__":
    main()
