"""Previous Greater Element for each position. IS: a left-to-right decreasing stack recording the last greater value. IS NOT: the next-greater variant."""

from __future__ import annotations

import ast

VERSION = "stack-43.v1"

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

def previous_greater(nums: list[int]) -> list[int]:
    """Previous greater value to the left (-1 if none). Fail-closed."""
    a = _req_int_list(nums, "nums")
    ans: list[int] = []
    stack: list[int] = []
    for x in a:
        while stack and stack[-1] <= x:
            stack.pop()
        ans.append(stack[-1] if stack else -1)
        stack.append(x)
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
    assert previous_greater([2, 1, 2, 4, 3]) == [-1, 2, -1, -1, 4]
    assert previous_greater([5, 4, 3, 2, 1]) == [-1, 5, 4, 3, 2]
    assert previous_greater([1, 2, 3]) == [-1, -1, -1]
    assert previous_greater([]) == []
    try:
        previous_greater([1, "x"])
    except ValueError:
        pass
    else:
        raise AssertionError("non-int must raise ValueError")
    assert stdlib_only()
    print("stack_43 OK")


if __name__ == "__main__":
    main()
