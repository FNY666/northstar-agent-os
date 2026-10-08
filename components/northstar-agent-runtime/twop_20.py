"""intersection_two_arrays (two-pointer), unique intersection of two sorted arrays. IS: two-pointer unique intersection of sorted lists. IS NOT: a set intersection that ignores sort order."""
from __future__ import annotations
import ast

VERSION = "twop-20.v1"

def intersection_two_arrays(a: list[int], b: list[int]) -> list[int]:
    """Return the sorted unique intersection of sorted lists a and b."""
    if not isinstance(a, list) or not isinstance(b, list):
        raise ValueError("a and b must be lists")
    out: list[int] = []
    i = 0
    j = 0
    while i < len(a) and j < len(b):
        if a[i] < b[j]:
            i += 1
        elif a[i] > b[j]:
            j += 1
        else:
            if not out or out[-1] != a[i]:
                out.append(a[i])
            i += 1
            j += 1
    return out

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
    assert intersection_two_arrays([1, 1, 2, 2], [2, 2]) == [2]
    assert intersection_two_arrays([4, 5, 9], [4, 4, 8, 9, 9]) == [4, 9]
    assert intersection_two_arrays([], [1, 2]) == []
    assert stdlib_only()
    print("intersection_two_arrays OK")

if __name__ == "__main__":
    main()
