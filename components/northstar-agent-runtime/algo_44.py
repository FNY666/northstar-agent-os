"""Longest increasing subsequence (LIS, strictly increasing) via patience sorting.

Maintain ``tails[k]`` = smallest possible tail value of an increasing
subsequence of length k+1; each element is placed with binary search and a
parent pointer records which earlier index it extends. Backtracking from the
last tail index reconstructs one LIS. Time O(n log n), space O(n).
``lis_length`` returns just the length.
"""

import ast
import sys
from pathlib import Path
from typing import List, Sequence

ALGO_44_VERSION = "algo-44.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys", "typing"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def lis(arr: Sequence[int]) -> List[int]:
    """Return one longest strictly-increasing subsequence of ``arr``."""
    arr = list(arr)
    n = len(arr)
    if n == 0:
        return []
    tails: List[int] = []        # smallest tail value per subsequence length
    tail_idx: List[int] = []    # index in arr of that tail
    parent: List[int] = [-1] * n
    for i, x in enumerate(arr):
        lo, hi = 0, len(tails)
        while lo < hi:  # lower_bound: first tail >= x (strict increase)
            mid = (lo + hi) // 2
            if tails[mid] < x:
                lo = mid + 1
            else:
                hi = mid
        if lo == len(tails):
            tails.append(x)
            tail_idx.append(i)
        else:
            tails[lo] = x
            tail_idx[lo] = i
        parent[i] = tail_idx[lo - 1] if lo > 0 else -1
    out: List[int] = []
    k = tail_idx[-1]
    while k != -1:
        out.append(arr[k])
        k = parent[k]
    out.reverse()
    return out


def lis_length(arr: Sequence[int]) -> int:
    """Return the length of the longest strictly-increasing subsequence."""
    return len(lis(arr))


def _valid_lis(sub: List[int], arr: Sequence[int]) -> bool:
    if not all(b > a for a, b in zip(sub, sub[1:])):
        return False
    it = iter(arr)
    return all(x in it for x in sub)


def main() -> None:
    got = lis([10, 9, 2, 5, 3, 7, 101, 18])
    assert len(got) == 4 and _valid_lis(got, [10, 9, 2, 5, 3, 7, 101, 18])
    assert lis([]) == [] and lis_length([]) == 0
    assert lis([7]) == [7]
    assert lis_length([5, 4, 3, 2, 1]) == 1
    assert lis_length([1, 2, 3, 4]) == 4
    assert lis_length([2, 2, 2]) == 1  # strictly increasing: equal values excluded
    assert stdlib_only()
    print("algo-44 OK")


if __name__ == "__main__":
    main()
