"""Next Greater Element I over a superset array. IS: a monotonic stack precomputing next-greater for nums2, then mapping nums1. IS NOT: a nested-loop search and assumes nums2 has distinct values."""

from __future__ import annotations

import ast

VERSION = "stack-05.v1"

def _req_nums(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    return list(values)


def next_greater_element(nums1: list[int], nums2: list[int]) -> list[int]:
    """Next greater value in ``nums2`` for each element of ``nums1`` (-1 if none).

    Fail-closed: both inputs must be int lists; ``nums2`` must have distinct
    values; every ``nums1`` element must appear in ``nums2``.
    """
    a = _req_nums(nums1, "nums1")
    b = _req_nums(nums2, "nums2")
    if len(set(b)) != len(b):
        raise ValueError("nums2 must have distinct values")
    nxt: dict[int, int] = {}
    stack: list[int] = []
    for x in b:
        while stack and stack[-1] < x:
            nxt[stack.pop()] = x
        stack.append(x)
    for x in stack:
        nxt[x] = -1
    out = []
    for x in a:
        if x not in nxt:
            raise ValueError(f"{x} not found in nums2")
        out.append(nxt[x])
    return out

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
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
    assert next_greater_element([4, 1, 2], [1, 3, 4, 2]) == [-1, 3, -1]
    assert next_greater_element([2, 4], [1, 2, 3, 4]) == [3, -1]
    assert next_greater_element([], [1, 2]) == []
    try:
        next_greater_element([1, 1], [1, 1])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate nums2 must raise ValueError")
    try:
        next_greater_element([9], [1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("missing element must raise ValueError")
    assert stdlib_only()
    print("stack_05 OK")


if __name__ == "__main__":
    main()
