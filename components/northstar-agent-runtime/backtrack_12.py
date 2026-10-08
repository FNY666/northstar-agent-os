"""Backtracking: subsets with duplicates.

IS: enumerate the full power set of ``nums`` (which may contain duplicate
values) while emitting each distinct subset exactly once. Sorting plus the
"skip equal neighbours at the same depth" rule (LeetCode 90) guarantees
no duplicate subsets and no missed ones.

IS NOT: dedup-by-set after generation (wasteful), subsets of a
deduplicated input (wrong: multiplicities matter), or permutations -
subset element order is normalized, never explored.

Self-test harness: run ``python backtrack_12.py``.
"""

from typing import List

VERSION = "backtrack_12.v1"

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


def subsets_with_dup(nums: List[int]) -> List[List[int]]:
    """All distinct subsets of nums (duplicates in input allowed)."""
    items = sorted(nums)
    results: List[List[int]] = []

    def dfs(start: int, path: List[int]) -> None:
        results.append(path.copy())
        for i in range(start, len(items)):
            if i > start and items[i] == items[i - 1]:
                continue  # skip duplicate branch at this depth
            path.append(items[i])
            dfs(i + 1, path)
            path.pop()

    dfs(0, [])
    return results


def main() -> None:
    norm = lambda subsets: sorted(sorted(s) for s in subsets)
    # Duplicates in input collapse in output.
    got = subsets_with_dup([1, 2, 2])
    assert norm(got) == norm([[], [1], [1, 2], [1, 2, 2], [2], [2, 2]]), got
    # Single element.
    got = subsets_with_dup([0])
    assert norm(got) == norm([[], [0]]), got
    # Empty input still yields the empty subset.
    assert subsets_with_dup([]) == [[]]
    # Count is the product of (multiplicity+1) over distinct values: 2^3 for
    # three distinct values, 3*2=6 for [1,2,2].
    assert len(subsets_with_dup([1, 2, 3])) == 8
    assert stdlib_only() is True
    print("backtrack_12 OK")


if __name__ == "__main__":
    main()
