"""Backtracking: Ones and zeroes -- given binary strings, maximize how many can
be formed using at most m zeros and n ones in total.

IS: recursive choice (take/skip) over the string list with (index, zeros,
ones) memoization -- backtracking shaped as a bounded 2-D knapsack search.
IS NOT: fractional selection, the lexicographic-order variant, or string
generation -- this module maximizes the count of usable strings only.
"""

from __future__ import annotations

VERSION = "backtrack_44.v1"


import ast
from typing import Dict, List, Tuple

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def _counts(s: str) -> Tuple[int, int]:
    return s.count("0"), s.count("1")


def max_form(strs: List[str], m: int, n: int) -> int:
    """Return the largest number of strings formable with at most m 0s and n 1s."""
    costs = [_counts(s) for s in strs]
    memo: Dict[Tuple[int, int, int], int] = {}

    def backtrack(i: int, zeros: int, ones: int) -> int:
        key = (i, zeros, ones)
        if key in memo:
            return memo[key]
        if i == len(strs):
            result = 0
        else:
            skip = backtrack(i + 1, zeros, ones)
            cz, co = costs[i]
            take = 0
            if zeros + cz <= m and ones + co <= n:
                take = 1 + backtrack(i + 1, zeros + cz, ones + co)
            result = skip if skip > take else take
        memo[key] = result
        return result

    return backtrack(0, 0, 0)


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


def main() -> None:
    assert stdlib_only()
    assert max_form(["10", "0001", "111001", "1", "0"], 5, 3) == 4
    assert max_form(["10", "0", "1"], 1, 1) == 2
    assert max_form(["00", "00", "11"], 2, 2) == 2
    assert max_form([], 3, 3) == 0
    assert max_form(["111", "111"], 1, 1) == 0
    print("backtrack_44 OK")


if __name__ == "__main__":
    main()
