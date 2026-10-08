"""Trapping Rain Water computed with a stack. IS: a monotonic stack that traps water between bars as valleys close. IS NOT: the two-pointer variant; equivalent result, stack mechanics."""

from __future__ import annotations

import ast

VERSION = "stack-07.v1"

def _req_height(height: object) -> list[int]:
    if not isinstance(height, list):
        raise ValueError("height must be a list")
    for h in height:
        if isinstance(h, bool) or not isinstance(h, int) or h < 0:
            raise ValueError("height must be non-negative ints")
    return list(height)


def trap_rain_water(height: list[int]) -> int:
    """Total trapped rain water. Fail-closed on bad input."""
    hs = _req_height(height)
    total = 0
    stack: list[int] = []
    for i, h in enumerate(hs):
        while stack and hs[stack[-1]] < h:
            bottom = stack.pop()
            if not stack:
                break
            left = stack[-1]
            width = i - left - 1
            bounded = min(hs[left], h) - hs[bottom]
            if bounded > 0:
                total += width * bounded
        stack.append(i)
    return total

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
    assert trap_rain_water([0, 1, 0, 2, 1, 0, 1, 3, 2, 1, 2, 1]) == 6
    assert trap_rain_water([4, 2, 0, 3, 2, 5]) == 9
    assert trap_rain_water([]) == 0
    assert trap_rain_water([5]) == 0
    assert trap_rain_water([1, 2, 3, 4]) == 0
    try:
        trap_rain_water("abc")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("stack_07 OK")


if __name__ == "__main__":
    main()
