"""remove_duplicates (two-pointer), drop duplicates from a sorted list in place. IS: in-place dedupe preserving order, returns new length. IS NOT: a general set-based unique (needs sorted input)."""
from __future__ import annotations
import ast

VERSION = "twop-11.v1"

def remove_duplicates(nums: list[int]) -> int:
    """Remove duplicates from sorted nums in place; return new length."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    n = len(nums)
    if n == 0:
        return 0
    write = 1
    for read in range(1, n):
        if nums[read] != nums[read - 1]:
            nums[write] = nums[read]
            write += 1
    return write

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
    a = [1, 1, 2, 3, 3, 3, 4]
    k = remove_duplicates(a)
    assert k == 4 and a[:k] == [1, 2, 3, 4], (k, a[:k])
    assert remove_duplicates([]) == 0
    b = [1, 1, 1]
    k2 = remove_duplicates(b)
    assert k2 == 1 and b[:k2] == [1], (k2, b[:k2])
    assert stdlib_only()
    print("remove_duplicates OK")

if __name__ == "__main__":
    main()
