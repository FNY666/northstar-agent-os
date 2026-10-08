"""move_zeroes (two-pointer), move all zeros to the end in place, stable. IS: stable in-place compaction preserving non-zero order. IS NOT: a swap-based sort (that would be unstable)."""
from __future__ import annotations
import ast

VERSION = "twop-14.v1"

def move_zeroes(nums: list[int]) -> None:
    """Move all zeros to the end of nums in place, preserving non-zero order."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    write = 0
    for read in range(len(nums)):
        if nums[read] != 0:
            nums[write] = nums[read]
            write += 1
    for i in range(write, len(nums)):
        nums[i] = 0

def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True

def main() -> None:
    a = [0, 1, 0, 3, 12]
    move_zeroes(a)
    assert a == [1, 3, 12, 0, 0], a
    b = [0]
    move_zeroes(b)
    assert b == [0], b
    c: list[int] = []
    move_zeroes(c)
    assert c == []
    assert stdlib_only()
    print("move_zeroes OK")

if __name__ == "__main__":
    main()
