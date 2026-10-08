"""Backtracking: combination sum II.

IS: find all *unique* combinations of candidates that sum to ``target``,
where each candidate may be used at most once and duplicate combinations
must not be repeated (classic LeetCode 40). The input is sorted once; at
each depth the loop skips a candidate equal to the previous one when it
is not the first choice at that depth, so each multiset is emitted once.

IS NOT: combination sum I (unlimited reuse of candidates), permutations
of the combos (order inside a combo is normalized by the sorted scan,
never explored), or counting combos instead of enumerating them.

Self-test harness: run ``python backtrack_11.py``.
"""

from typing import List

VERSION = "backtrack_11.v1"

_ALLOWED_IMPORTS = frozenset({"typing", "dataclasses", "itertools", "ast"})


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import comes from the
    allowed stdlib set."""
    import ast

    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return False
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def combination_sum_2(candidates: List[int], target: int) -> List[List[int]]:
    """All unique combos of candidates (each used <= once) summing to target."""
    nums = sorted(candidates)
    results: List[List[int]] = []

    def dfs(start: int, remaining: int, path: List[int]) -> None:
        if remaining == 0:
            results.append(path.copy())
            return
        for i in range(start, len(nums)):
            if i > start and nums[i] == nums[i - 1]:
                continue  # skip duplicate branch at this depth
            if nums[i] > remaining:
                break
            path.append(nums[i])
            dfs(i + 1, remaining - nums[i], path)
            path.pop()

    dfs(0, target, [])
    return results


def main() -> None:
    norm = lambda combos: sorted(sorted(c) for c in combos)
    # Classic example: duplicates in input, dedup in output.
    got = combination_sum_2([10, 1, 2, 7, 6, 1, 5], 8)
    assert norm(got) == norm([[1, 1, 6], [1, 2, 5], [1, 7], [2, 6]]), got
    # Input duplicates must not duplicate combos.
    got = combination_sum_2([2, 5, 2, 1, 2], 5)
    assert norm(got) == norm([[1, 2, 2], [5]]), got
    # No possible combo -> empty.
    assert combination_sum_2([3, 4, 5], 2) == []
    # Each candidate used at most once: 2+2+3 is impossible from [2, 3].
    assert combination_sum_2([2, 3], 7) == []
    assert stdlib_only() is True
    print("backtrack_11 OK")


if __name__ == "__main__":
    main()
