"""Backtracking: tug of war - split into two near-equal teams.

IS: partitions the numbers into two groups whose sizes differ by at most
one while minimizing the absolute difference of the group sums, via
choose-half backtracking. IS NOT: a claim that the optimum found is
"fair" in any real-world sense - it is a pure combinatorial minimizer,
and it is exponential, so it suits small rosters only.
"""

import ast
from typing import List, Optional, Tuple

VERSION = "backtrack_24.v1"


def tug_of_war(nums: List[int]) -> Tuple[List[int], List[int]]:
    """Return (team1, team2) minimizing |sum1 - sum2| with |len1 - len2| <= 1."""
    n = len(nums)
    size1 = n // 2
    total = sum(nums)
    chosen = [False] * n
    best = {"diff": None, "mask": None}

    def dfs(i: int, count: int, s1: int) -> None:
        if count == size1:
            diff = abs(total - 2 * s1)
            if best["diff"] is None or diff < best["diff"]:
                best["diff"] = diff
                best["mask"] = chosen.copy()
            return
        if i == n:
            return
        if count + (n - i) < size1:
            return
        chosen[i] = True
        dfs(i + 1, count + 1, s1 + nums[i])
        chosen[i] = False
        dfs(i + 1, count, s1)

    dfs(0, 0, 0)
    mask = best["mask"] or [False] * n
    team1 = [nums[i] for i in range(n) if mask[i]]
    team2 = [nums[i] for i in range(n) if not mask[i]]
    return team1, team2


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    t1, t2 = tug_of_war([1, 2, 3, 4])
    assert abs(sum(t1) - sum(t2)) == 0
    assert abs(len(t1) - len(t2)) <= 1
    assert sorted(t1 + t2) == [1, 2, 3, 4]
    t1, t2 = tug_of_war([1, 2])
    assert abs(sum(t1) - sum(t2)) == 1
    t1, t2 = tug_of_war([3, 4, 5, -3, 100, 1, 89, 54, 23, 20])
    assert abs(sum(t1) - sum(t2)) == 0
    assert len(t1) == 5 and len(t2) == 5
    assert sorted(t1 + t2) == sorted([3, 4, 5, -3, 100, 1, 89, 54, 23, 20])
    print("backtrack_24 OK")


if __name__ == "__main__":
    main()
