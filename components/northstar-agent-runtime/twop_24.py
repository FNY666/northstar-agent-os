"""Symmetric Difference Sorted (two-pointer), elements in exactly one of A, B. IS: merges two sorted lists, cancelling one copy of each value common to both, and returning the rest in sorted order. IS NOT: a union; a value present in both inputs (up to shared multiplicities) is dropped, and unsorted input is rejected."""
from __future__ import annotations

import ast

VERSION = "twop-24.v1"


def _require_sorted(values: list[int], name: str) -> None:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    for i in range(len(values) - 1):
        if values[i] > values[i + 1]:
            raise ValueError(f"{name} must be sorted in non-decreasing order")


def symmetric_difference_sorted(a: list[int], b: list[int]) -> list[int]:
    """Return sorted elements that appear in exactly one of the two sorted lists."""
    _require_sorted(a, "a")
    _require_sorted(b, "b")
    out: list[int] = []
    i = 0
    j = 0
    while i < len(a) and j < len(b):
        if a[i] < b[j]:
            out.append(a[i])
            i += 1
        elif b[j] < a[i]:
            out.append(b[j])
            j += 1
        else:
            i += 1
            j += 1
    out.extend(a[i:])
    out.extend(b[j:])
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
    assert symmetric_difference_sorted([1, 1, 2], [1, 3]) == [1, 2, 3]
    assert symmetric_difference_sorted([1, 2], [1, 2]) == []
    assert symmetric_difference_sorted([], [3]) == [3]
    assert symmetric_difference_sorted([4, 5], [1, 4]) == [1, 5]
    try:
        symmetric_difference_sorted([3, 2], [1])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    print("twop-24 OK")


if __name__ == "__main__":
    main()
