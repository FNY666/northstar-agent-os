"""132 Pattern detection with a decreasing stack. IS: a right-to-left scan keeping a stack of '3' candidates and a '2' bound. IS NOT: an O(n^2) triple loop."""

from __future__ import annotations

import ast

VERSION = "stack-17.v1"

def _req_ints(nums: object) -> list[int]:
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    for v in nums:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("nums must contain only ints")
    return list(nums)


def find_132_pattern(nums: list[int]) -> bool:
    """True iff some i<j<k has nums[i] < nums[k] < nums[j]. Fail-closed."""
    a = _req_ints(nums)
    third = float("-inf")
    stack: list[int] = []
    for x in reversed(a):
        if x < third:
            return True
        while stack and stack[-1] < x:
            third = stack.pop()
        stack.append(x)
    return False

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
    assert find_132_pattern([1, 2, 3, 4]) is False
    assert find_132_pattern([3, 1, 4, 2]) is True
    assert find_132_pattern([-1, 3, 2, 0]) is True
    assert find_132_pattern([1, 2]) is False
    assert find_132_pattern([]) is False
    try:
        find_132_pattern([1, "2"])
    except ValueError:
        pass
    else:
        raise AssertionError("non-int must raise ValueError")
    assert stdlib_only()
    print("stack_17 OK")


if __name__ == "__main__":
    main()
