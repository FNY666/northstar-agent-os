"""Reverse Array (two-pointer), in-place reversal. IS: reverses a list of ints in place using two pointers that swap from both ends toward the middle. IS NOT: a copy-returning helper; the input list itself is mutated and nothing is returned."""
from __future__ import annotations

import ast

VERSION = "twop-25.v1"


def reverse_array(arr: list[int]) -> None:
    """Reverse the list of ints in place."""
    if not isinstance(arr, list):
        raise ValueError("input must be a list")
    for v in arr:
        if not isinstance(v, int):
            raise ValueError("list must contain only ints")
    lo = 0
    hi = len(arr) - 1
    while lo < hi:
        arr[lo], arr[hi] = arr[hi], arr[lo]
        lo += 1
        hi -= 1


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] not in allowed for alias in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    arr = [1, 2, 3, 4]
    reverse_array(arr)
    assert arr == [4, 3, 2, 1]
    odd = [1, 2, 3]
    reverse_array(odd)
    assert odd == [3, 2, 1]
    empty: list[int] = []
    reverse_array(empty)
    assert empty == []
    single = [7]
    reverse_array(single)
    assert single == [7]
    try:
        reverse_array("not-a-list")  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-list input")
    print("twop-25 OK")


if __name__ == "__main__":
    main()
