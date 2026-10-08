"""Memoized Combination Sum IV: memoization example.

Count ordered combinations summing to target: dp(t) = sum(dp(t - x)) over coins x. The target cache gives O(target * |nums|).

What this IS: a real memoized ordered-combination counter, fail-closed on negative target.
What this IS NOT: an unordered combination counter (see memo-05); the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_25_VERSION = "memo-combination-sum-iv.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-combination-sum-iv.v1"


class MemoError(Exception):
    """Fail-closed."""


def comb_sum4(nums: tuple, target: int, _cache: dict | None = None) -> int:
    """Memoized combination-sum-IV counter. Fail-closed on target < 0."""
    if target < 0:
        raise MemoError("comb_sum4 needs target >= 0")
    cache: dict = _cache if _cache is not None else {}
    if target in cache:
        return cache[target]
    if target == 0:
        cache[target] = 1
    else:
        cache[target] = sum(comb_sum4(nums, target - x, cache) for x in nums if x <= target)
    return cache[target]

def test_comb_sum4_example():
    assert comb_sum4((1, 2, 3), 4) == 7


def test_comb_sum4_zero():
    assert comb_sum4((1, 2), 0) == 1


def test_comb_sum4_negative_raises():
    try:
        comb_sum4((1,), -2)
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
    test_comb_sum4_example()
    test_comb_sum4_zero()
    test_comb_sum4_negative_raises()
    assert stdlib_only()
    print("memo-25 OK: combination-sum-iv")


if __name__ == "__main__":
    main()
