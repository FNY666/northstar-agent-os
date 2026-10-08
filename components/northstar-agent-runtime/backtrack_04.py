"""Backtracking: Combinations (n choose k).

Generates all k-element combinations of the integers 1..n via backtracking
that advances the start index to keep elements in increasing order.

IS: all C(n,k) combinations, each in increasing order, for 0 <= k <= n.
IS NOT: permutations (order does not matter here); NOT combinations-with-repetition.
"""

from typing import List
import ast

VERSION = "backtrack_04.v1"


def combinations(n: int, k: int) -> List[List[int]]:
    result: List[List[int]] = []
    combo: List[int] = []

    def backtrack(start: int) -> None:
        if len(combo) == k:
            result.append(list(combo))
            return
        for i in range(start, n + 1):
            combo.append(i)
            backtrack(i + 1)
            combo.pop()

    backtrack(1)
    return result


def stdlib_only() -> bool:
    allowed = {"typing", "ast"}
    with open(__file__) as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    c = combinations(4, 2)
    assert len(c) == 6
    assert sorted(tuple(x) for x in c) == sorted(
        [(1, 2), (1, 3), (1, 4), (2, 3), (2, 4), (3, 4)]
    )
    assert combinations(5, 0) == [[]]
    assert combinations(3, 3) == [[1, 2, 3]]
    assert len(combinations(10, 3)) == 120
    assert stdlib_only()
    print("backtrack_04 OK")


if __name__ == "__main__":
    main()
