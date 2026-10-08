"""Difference Sorted (two-pointer), elements in A not in B from sorted inputs. IS: returns the elements of the first sorted list that do not appear in the second, preserving order and duplicates of non-common elements. IS NOT: a set difference on multisets; every copy of a value present in B is removed, and unsorted input is rejected."""
from __future__ import annotations

import ast

VERSION = "twop-23.v1"


def _require_sorted(values: list[int], name: str) -> None:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    for i in range(len(values) - 1):
        if values[i] > values[i + 1]:
            raise ValueError(f"{name} must be sorted in non-decreasing order")


def difference_sorted(a: list[int], b: list[int]) -> list[int]:
    """Return elements of sorted list A that are not in sorted list B."""
    _require_sorted(a, "a")
    _require_sorted(b, "b")
    out: list[int] = []
    i = 0
    j = 0
    while i < len(a) and j < len(b):
        if a[i] < b[j]:
            out.append(a[i])
            i += 1
        elif a[i] == b[j]:
            v = a[i]
            while i < len(a) and a[i] == v:
                i += 1
            while j < len(b) and b[j] == v:
                j += 1
        else:
            j += 1
    while i < len(a):
        out.append(a[i])
        i += 1
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
    assert difference_sorted([1, 1, 2, 3], [1, 4]) == [2, 3]
    assert difference_sorted([1, 2], []) == [1, 2]
    assert difference_sorted([1], [1, 2]) == []
    assert difference_sorted([2, 2, 2], [2]) == []
    try:
        difference_sorted([1], [2, 1])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    print("twop-23 OK")


if __name__ == "__main__":
    main()
