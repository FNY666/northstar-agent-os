"""Backtracking: Combination sum (candidates may repeat).

Finds all unique combinations of candidate numbers (each usable unlimited
times) that sum to the target, using sorted candidates with the same start
index for reuse and a skip rule for duplicate candidates.

IS: unique combos summing to target with unlimited reuse of each candidate.
IS NOT: the each-candidate-once variant; NOT a permutation enumerator.
"""

from typing import List
import ast

VERSION = "backtrack_10.v1"


def combination_sum(candidates: List[int], target: int) -> List[List[int]]:
    candidates = sorted(candidates)
    result: List[List[int]] = []
    combo: List[int] = []

    def backtrack(start: int, remaining: int) -> None:
        if remaining == 0:
            result.append(list(combo))
            return
        prev = None
        for i in range(start, len(candidates)):
            c = candidates[i]
            if c == prev:
                continue
            if c > remaining:
                break
            combo.append(c)
            backtrack(i, remaining - c)
            combo.pop()
            prev = c

    backtrack(0, target)
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
    r = combination_sum([2, 3, 6, 7], 7)
    assert sorted(tuple(x) for x in r) == sorted([(2, 2, 3), (7,)])
    assert combination_sum([2, 3, 5], 8) and sorted(
        tuple(x) for x in combination_sum([2, 3, 5], 8)
    ) == sorted([(2, 2, 2, 2), (2, 3, 3), (3, 5)])
    assert combination_sum([2], 1) == []
    assert combination_sum([2, 2, 3], 7) == [[2, 2, 3]]
    assert stdlib_only()
    print("backtrack_10 OK")


if __name__ == "__main__":
    main()
