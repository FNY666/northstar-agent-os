"""Next Greater Element II on a circular array. IS: a monotonic stack over a doubled traversal of the circular array. IS NOT: an O(n^2) wrap-around scan."""

from __future__ import annotations

import ast

VERSION = "stack-19.v1"

def _req_ints(nums: object) -> list[int]:
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    for v in nums:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("nums must contain only ints")
    return list(nums)


def next_greater_circular(nums: list[int]) -> list[int]:
    """Next greater element wrapping around (-1 if none). Fail-closed."""
    a = _req_ints(nums)
    n = len(a)
    ans = [-1] * n
    stack: list[int] = []
    for i in range(2 * n):
        j = i % n
        while stack and a[stack[-1]] < a[j]:
            ans[stack.pop()] = a[j]
        if i < n:
            stack.append(j)
    return ans

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
    assert next_greater_circular([1, 2, 1]) == [2, -1, 2]
    assert next_greater_circular([1, 2, 3, 4, 3]) == [2, 3, 4, -1, 4]
    assert next_greater_circular([5, 4, 3, 2, 1]) == [-1, 5, 5, 5, 5]
    assert next_greater_circular([]) == []
    assert next_greater_circular([7]) == [-1]
    try:
        next_greater_circular([1.5])
    except ValueError:
        pass
    else:
        raise AssertionError("non-int must raise ValueError")
    assert stdlib_only()
    print("stack_19 OK")


if __name__ == "__main__":
    main()
