"""Largest Rectangle in Histogram via monotonic stack. IS: a single-pass increasing stack computing max width x height. IS NOT: a divide-and-conquer or brute-force enumeration."""

from __future__ import annotations

import ast

VERSION = "stack-06.v1"

def _req_heights(heights: object) -> list[int]:
    if not isinstance(heights, list):
        raise ValueError("heights must be a list")
    for h in heights:
        if isinstance(h, bool) or not isinstance(h, int) or h < 0:
            raise ValueError("heights must be non-negative ints")
    return list(heights)


def largest_rectangle(heights: list[int]) -> int:
    """Largest rectangle area in the histogram. Fail-closed on bad input."""
    hs = _req_heights(heights)
    best = 0
    stack: list[int] = []
    for i, h in enumerate(hs + [0]):
        while stack and hs[stack[-1]] > h:
            height = hs[stack.pop()]
            width = i if not stack else i - stack[-1] - 1
            best = max(best, height * width)
        stack.append(i)
    return best

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
    assert largest_rectangle([2, 1, 5, 6, 2, 3]) == 10
    assert largest_rectangle([2, 4]) == 4
    assert largest_rectangle([]) == 0
    assert largest_rectangle([5]) == 5
    assert largest_rectangle([1, 1, 1, 1]) == 4
    try:
        largest_rectangle([-1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("negative height must raise ValueError")
    assert stdlib_only()
    print("stack_06 OK")


if __name__ == "__main__":
    main()
