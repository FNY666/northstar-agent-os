"""remove_duplicates_ii (two-pointer), allow at most two copies in a sorted list in place. IS: in-place filter keeping <=2 duplicates, returns new length. IS NOT: a set unique or a counter."""
from __future__ import annotations
import ast

VERSION = "twop-12.v1"

def remove_duplicates_ii(nums: list[int]) -> int:
    """Keep at most two of each value in sorted nums in place; return new length."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    write = 0
    for x in nums:
        if write < 2 or x != nums[write - 2]:
            nums[write] = x
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
    a = [1, 1, 1, 2, 2, 3]
    k = remove_duplicates_ii(a)
    assert k == 5 and a[:k] == [1, 1, 2, 2, 3], (k, a[:k])
    assert remove_duplicates_ii([]) == 0
    b = [0, 0, 1, 1, 1, 1, 2, 3, 3]
    k2 = remove_duplicates_ii(b)
    assert k2 == 7 and b[:k2] == [0, 0, 1, 1, 2, 3, 3], (k2, b[:k2])
    assert stdlib_only()
    print("remove_duplicates_ii OK")

if __name__ == "__main__":
    main()
