"""Number of Visible People in a Queue. IS: a decreasing stack counting how many to the right each person sees. IS NOT: an O(n^2) line-of-sight scan."""

from __future__ import annotations

import ast

VERSION = "stack-45.v1"

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

def count_visible_people(heights: list[int]) -> list[int]:
    """Visible people to the right of each position. Fail-closed."""
    hs = _req_int_list(heights, "heights")
    if any(h < 0 for h in hs):
        raise ValueError("heights must be non-negative")
    n = len(hs)
    ans = [0] * n
    stack: list[int] = []
    for i in range(n - 1, -1, -1):
        while stack and hs[stack[-1]] < hs[i]:
            ans[i] += 1
            stack.pop()
        if stack:
            ans[i] += 1
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
    assert count_visible_people([10, 6, 8, 5, 11, 9]) == [3, 1, 2, 1, 1, 0]
    assert count_visible_people([5, 1, 2, 3, 10]) == [4, 1, 1, 1, 0]
    assert count_visible_people([1]) == [0]
    assert count_visible_people([]) == []
    try:
        count_visible_people([-2])
    except ValueError:
        pass
    else:
        raise AssertionError("negative must raise ValueError")
    assert stdlib_only()
    print("stack_45 OK")


if __name__ == "__main__":
    main()
