"""Memoized House Robber: memoization example.

Max loot from non-adjacent houses: rob(i) = max(nums[i] + rob(i+2), rob(i+1)). The index-keyed cache makes the recursion linear.

What this IS: a real O(n) memoized robber DP over an index cache, fail-closed on negative index.
What this IS NOT: a circular-street variant; the host picks the problem shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_04_VERSION = "memo-house-robber.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-house-robber.v1"


class MemoError(Exception):
    """Fail-closed."""


def rob(nums: tuple, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized house robber. Fail-closed on i < 0."""
    if i < 0:
        raise MemoError("rob needs i >= 0")
    cache: dict = _cache if _cache is not None else {}
    if i in cache:
        return cache[i]
    if i >= len(nums):
        cache[i] = 0
    else:
        cache[i] = max(nums[i] + rob(nums, i + 2, cache), rob(nums, i + 1, cache))
    return cache[i]

def test_rob_example():
    assert rob((2, 7, 9, 3, 1)) == 12


def test_rob_small():
    assert rob((1, 2, 3, 1)) == 4


def test_rob_empty():
    assert rob(()) == 0


def test_rob_negative_index_raises():
    try:
        rob((1, 2), -1)
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
    test_rob_example()
    test_rob_small()
    test_rob_empty()
    test_rob_negative_index_raises()
    assert stdlib_only()
    print("memo-04 OK: house-robber")


if __name__ == "__main__":
    main()
