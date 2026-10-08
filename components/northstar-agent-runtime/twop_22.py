"""Union Sorted Unique (two-pointer), sorted union without duplicates. IS: merges two sorted lists into one sorted list with each distinct value appearing exactly once. IS NOT: a concatenation; duplicates within and across inputs are removed, and unsorted input is rejected."""
from __future__ import annotations

import ast

VERSION = "twop-22.v1"


def _require_sorted(values: list[int], name: str) -> None:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    for i in range(len(values) - 1):
        if values[i] > values[i + 1]:
            raise ValueError(f"{name} must be sorted in non-decreasing order")


def union_sorted_unique(a: list[int], b: list[int]) -> list[int]:
    """Return the sorted union of two sorted lists, with no duplicates."""
    _require_sorted(a, "a")
    _require_sorted(b, "b")
    out: list[int] = []

    def push(v: int) -> None:
        if not out or out[-1] != v:
            out.append(v)

    i = 0
    j = 0
    while i < len(a) and j < len(b):
        if a[i] < b[j]:
            push(a[i])
            i += 1
        elif b[j] < a[i]:
            push(b[j])
            j += 1
        else:
            push(a[i])
            i += 1
            j += 1
    while i < len(a):
        push(a[i])
        i += 1
    while j < len(b):
        push(b[j])
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
    assert union_sorted_unique([1, 2, 2, 3], [2, 3, 4, 4]) == [1, 2, 3, 4]
    assert union_sorted_unique([], []) == []
    assert union_sorted_unique([5], [5]) == [5]
    assert union_sorted_unique([-3, -3, 0], [-3, 1]) == [-3, 0, 1]
    try:
        union_sorted_unique([1, 3, 2], [1])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    print("twop-22 OK")


if __name__ == "__main__":
    main()
