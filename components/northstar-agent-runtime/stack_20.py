"""Sum of Subarray Minimums with boundary stacks. IS: two monotonic stacks finding each element's dominance span. IS NOT: enumerating all subarrays."""

from __future__ import annotations

import ast

VERSION = "stack-20.v1"

def _req_arr(arr: object) -> list[int]:
    if not isinstance(arr, list):
        raise ValueError("arr must be a list")
    for v in arr:
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError("arr must contain non-negative ints")
    return list(arr)


def sum_subarray_minimums(arr: list[int]) -> int:
    """Sum of minimums of all subarrays, mod 1e9+7. Fail-closed."""
    a = _req_arr(arr)
    n = len(a)
    left = [0] * n
    right = [0] * n
    stack: list[int] = []
    for i in range(n):
        while stack and a[stack[-1]] > a[i]:
            stack.pop()
        left[i] = i - (stack[-1] if stack else -1)
        stack.append(i)
    stack.clear()
    for i in range(n - 1, -1, -1):
        while stack and a[stack[-1]] >= a[i]:
            stack.pop()
        right[i] = (stack[-1] if stack else n) - i
        stack.append(i)
    return sum(a[i] * left[i] * right[i] for i in range(n)) % 1_000_000_007

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
    assert sum_subarray_minimums([3, 1, 2, 4]) == 17
    assert sum_subarray_minimums([11, 81, 94, 43, 3]) == 444
    assert sum_subarray_minimums([5]) == 5
    assert sum_subarray_minimums([]) == 0
    assert sum_subarray_minimums([2, 2, 2]) == 12
    try:
        sum_subarray_minimums([-1])
    except ValueError:
        pass
    else:
        raise AssertionError("negative must raise ValueError")
    assert stdlib_only()
    print("stack_20 OK")


if __name__ == "__main__":
    main()
