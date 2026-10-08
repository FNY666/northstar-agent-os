"""Next Smaller Element for each position. IS: a left-to-right increasing stack recording the next smaller value. IS NOT: the next-greater variant."""

from __future__ import annotations

import ast

VERSION = "stack-44.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_int_list(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    return list(values)

def next_smaller(nums: list[int]) -> list[int]:
    """Next smaller value to the right (-1 if none). Fail-closed."""
    a = _req_int_list(nums, "nums")
    n = len(a)
    ans = [-1] * n
    stack: list[int] = []
    for i, x in enumerate(a):
        while stack and a[stack[-1]] > x:
            ans[stack.pop()] = x
        stack.append(i)
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
    assert next_smaller([4, 2, 1, 5, 3]) == [2, 1, -1, 3, -1]
    assert next_smaller([1, 2, 3]) == [-1, -1, -1]
    assert next_smaller([3, 2, 1]) == [2, 1, -1]
    assert next_smaller([]) == []
    try:
        next_smaller("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("stack_44 OK")


if __name__ == "__main__":
    main()
