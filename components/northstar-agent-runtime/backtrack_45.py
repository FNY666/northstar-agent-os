"""Backtracking: Beautiful arrangement -- count permutations of 1..n such that for
every 1-based position i, perm[i] % i == 0 or i % perm[i] == 0.

IS: position-by-position permutation search with the divisibility test as the
pruning rule, counting only valid full arrangements.
IS NOT: k-th arrangement retrieval, lexicographic ranking, or the
derangement/permutation-cycle variants -- this module counts arrangements.
"""

from __future__ import annotations

VERSION = "backtrack_45.v1"


import ast

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def count_arrangement(n: int) -> int:
    """Count beautiful arrangements of 1..n."""
    used = [False] * (n + 1)

    def backtrack(pos: int) -> int:
        if pos > n:
            return 1
        total = 0
        for num in range(1, n + 1):
            if not used[num] and (num % pos == 0 or pos % num == 0):
                used[num] = True
                total += backtrack(pos + 1)
                used[num] = False
        return total

    return backtrack(1)


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def _valid(arr):
    return all((v % (i + 1) == 0 or (i + 1) % v == 0) for i, v in enumerate(arr))


def main() -> None:
    assert stdlib_only()
    assert count_arrangement(1) == 1
    assert count_arrangement(2) == 2
    assert count_arrangement(3) == 3
    assert count_arrangement(4) == 8
    assert count_arrangement(5) == 10
    print("backtrack_45 OK")


if __name__ == "__main__":
    main()
