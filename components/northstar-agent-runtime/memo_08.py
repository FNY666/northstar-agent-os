"""Memoized 0/1 Knapsack: memoization example.

Max value under capacity: ks(i, cap) = max(value[i] + ks(i+1, cap-w[i]), ks(i+1, cap)). The (i, cap) cache gives O(n*cap).

What this IS: a real memoized 0/1 knapsack, fail-closed on negative capacity.
What this IS NOT: a fractional knapsack solver; the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_08_VERSION = "memo-knapsack.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-knapsack.v1"


class MemoError(Exception):
    """Fail-closed."""


def knapsack(weights: tuple, values: tuple, cap: int, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized 0/1 knapsack max value. Fail-closed on cap < 0."""
    if cap < 0:
        raise MemoError("knapsack needs cap >= 0")
    cache: dict = _cache if _cache is not None else {}
    key = (i, cap)
    if key in cache:
        return cache[key]
    if i >= len(weights) or cap == 0:
        cache[key] = 0
    elif weights[i] > cap:
        cache[key] = knapsack(weights, values, cap, i + 1, cache)
    else:
        cache[key] = max(
            values[i] + knapsack(weights, values, cap - weights[i], i + 1, cache),
            knapsack(weights, values, cap, i + 1, cache),
        )
    return cache[key]

def test_knapsack_example():
    assert knapsack((1, 3, 4, 5), (1, 4, 5, 7), 7) == 9


def test_knapsack_empty():
    assert knapsack((), (), 10) == 0


def test_knapsack_negative_cap_raises():
    try:
        knapsack((1,), (1,), -1)
    except MemoError:
        return
    raise AssertionError("expected MemoError")

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
    test_knapsack_example()
    test_knapsack_empty()
    test_knapsack_negative_cap_raises()
    assert stdlib_only()
    print("memo-08 OK: knapsack")


if __name__ == "__main__":
    main()
