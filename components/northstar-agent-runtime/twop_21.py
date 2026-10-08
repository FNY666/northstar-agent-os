"""Intersection II (two-pointer), intersection with duplicates of two sorted arrays. IS: returns elements common to both sorted inputs, preserving duplicate multiplicities. IS NOT: a set intersection; duplicates are kept and unsorted input is rejected, not silently sorted."""
from __future__ import annotations

import ast

VERSION = "twop-21.v1"


def _require_sorted(values: list[int], name: str) -> None:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    for i in range(len(values) - 1):
        if values[i] > values[i + 1]:
            raise ValueError(f"{name} must be sorted in non-decreasing order")


def intersection_two_arrays_ii(a: list[int], b: list[int]) -> list[int]:
    """Return the intersection of two sorted lists, keeping duplicate copies."""
    _require_sorted(a, "a")
    _require_sorted(b, "b")
    out: list[int] = []
    i = 0
    j = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            out.append(a[i])
            i += 1
            j += 1
        elif a[i] < b[j]:
            i += 1
        else:
            j += 1
    return out


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
    assert intersection_two_arrays_ii([1, 2, 2, 3], [2, 2, 4]) == [2, 2]
    assert intersection_two_arrays_ii([1, 2, 3], [4, 5, 6]) == []
    assert intersection_two_arrays_ii([], [1, 2]) == []
    assert intersection_two_arrays_ii([1, 1, 1], [1, 1]) == [1, 1]
    try:
        intersection_two_arrays_ii([2, 1], [1])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    print("twop-21 OK")


if __name__ == "__main__":
    main()
