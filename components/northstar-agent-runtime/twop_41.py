"""max_consecutive_ones (two-pointer), longest run of 1s in a binary list. IS: a linear scan tracking the longest consecutive run of 1s. IS NOT: a counter of total 1s or a window that flips 0s."""
from __future__ import annotations

import ast

VERSION = "twop-41.v1"


def max_consecutive_ones(nums: list[int]) -> int:
    """Return the length of the longest run of consecutive 1s in nums."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    for v in nums:
        if isinstance(v, bool) or v not in (0, 1):
            raise ValueError("nums must contain only 0s and 1s")
    best = 0
    cur = 0
    for v in nums:
        if v == 1:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert max_consecutive_ones([1, 1, 0, 1, 1, 1]) == 3
    assert max_consecutive_ones([1, 0, 1, 0, 1, 0]) == 1
    assert max_consecutive_ones([0, 0, 0]) == 0  # edge: no 1s at all
    assert max_consecutive_ones([]) == 0
    try:
        max_consecutive_ones([1, 2, 1])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-binary input")
    assert stdlib_only()
    print("max_consecutive_ones OK")


if __name__ == "__main__":
    main()
