"""merge_sorted_arrays (two-pointer), merge B into A's trailing buffer in place from the end. IS: in-place merge of two sorted arrays, back-to-front. IS NOT: an allocation-based merge (no extra output list)."""
from __future__ import annotations
import ast

VERSION = "twop-18.v1"

def merge_sorted_arrays(a: list[int], m: int, b: list[int], n: int) -> None:
    """Merge sorted b into a in place; a's first m entries are valid with n free slots at the end."""
    if not isinstance(a, list) or not isinstance(b, list):
        raise ValueError("a and b must be lists")
    if not isinstance(m, int) or not isinstance(n, int):
        raise ValueError("m and n must be ints")
    if m < 0 or n < 0 or m + n != len(a) or len(b) < n:
        raise ValueError("m/n must fit a's length and b's length")
    i = m - 1
    j = n - 1
    write = m + n - 1
    while j >= 0:
        if i >= 0 and a[i] > b[j]:
            a[write] = a[i]
            i -= 1
        else:
            a[write] = b[j]
            j -= 1
        write -= 1

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
    a = [1, 2, 3, 0, 0, 0]
    merge_sorted_arrays(a, 3, [2, 5, 6], 3)
    assert a == [1, 2, 2, 3, 5, 6], a
    b = [1]
    merge_sorted_arrays(b, 1, [], 0)
    assert b == [1], b
    c = [0, 0]
    merge_sorted_arrays(c, 0, [4, 5], 2)
    assert c == [4, 5], c
    assert stdlib_only()
    print("merge_sorted_arrays OK")

if __name__ == "__main__":
    main()
