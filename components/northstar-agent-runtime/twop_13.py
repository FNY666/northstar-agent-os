"""remove_element (two-pointer), remove all occurrences of a value in place. IS: in-place filter removing every val, returns new length. IS NOT: a filter that builds a new list."""
from __future__ import annotations
import ast

VERSION = "twop-13.v1"

def remove_element(nums: list[int], val: int) -> int:
    """Remove all occurrences of val from nums in place; return new length."""
    if not isinstance(nums, list):
        raise ValueError("nums must be a list")
    if not isinstance(val, int):
        raise ValueError("val must be an int")
    write = 0
    for x in nums:
        if x != val:
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
    a = [3, 2, 2, 3]
    k = remove_element(a, 3)
    assert k == 2 and a[:k] == [2, 2], (k, a[:k])
    assert remove_element([], 1) == 0
    b = [0, 1, 2, 2, 3, 0, 4, 2]
    k2 = remove_element(b, 2)
    assert k2 == 5 and a is not None and b[:k2] == [0, 1, 3, 0, 4], (k2, b[:k2])
    assert stdlib_only()
    print("remove_element OK")

if __name__ == "__main__":
    main()
