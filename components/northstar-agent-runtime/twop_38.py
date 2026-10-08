"""kth_from_end (two-pointer), kth element from the end of a list. IS: exact 1-indexed lookup (k=1 is the last element) via fast/slow pointer gap. IS NOT: negative indexing; k must satisfy 1 <= k <= len(items)."""
from __future__ import annotations

import ast

VERSION = "twop-38.v1"


def kth_from_end(items: list, k: int) -> object:
    if not isinstance(items, list):
        raise ValueError("items must be a list")
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an integer")
    if k < 1 or k > len(items):
        raise ValueError("k out of range: need 1 <= k <= len(items)")
    fast = 0
    for _ in range(k):
        fast += 1
    slow = 0
    while fast < len(items):
        fast += 1
        slow += 1
    return items[slow]


def stdlib_only() -> bool:
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text())
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
    assert kth_from_end([1, 2, 3, 4, 5], 1) == 5
    assert kth_from_end([1, 2, 3, 4, 5], 5) == 1
    assert kth_from_end(["a", "b", "c"], 2) == "b"
    assert kth_from_end([42], 1) == 42  # edge: single-element list
    for bad in (0, -1, 6):
        try:
            kth_from_end([1, 2, 3, 4, 5], bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"k={bad} must raise ValueError")
    try:
        kth_from_end([], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty list must raise ValueError")
    assert stdlib_only()
    print("twop_38 OK")


if __name__ == "__main__":
    main()
