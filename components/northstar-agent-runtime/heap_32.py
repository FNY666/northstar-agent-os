"""Reduce Array Size to the Half: smallest set whose removal halves the array IS: max-heap of frequencies IS NOT: trying every removal set"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-32.v1"

def _req_arr(value):
    if not isinstance(value, list) or not value:
        raise ValueError("arr must be a non-empty list")
    return list(value)


def min_set_size(arr):
    """Return the smallest set size whose removal halves ``arr``.

    Fail-closed: ``arr`` must be a non-empty list, else :class:`ValueError`.
    """
    arr = _req_arr(arr)
    freq = {}
    for x in arr:
        freq[x] = freq.get(x, 0) + 1
    heap = [-c for c in freq.values()]
    heapq.heapify(heap)
    removed = 0
    target = (len(arr) + 1) // 2
    count = 0
    while removed < target:
        removed += -heapq.heappop(heap)
        count += 1
    return count

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
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
    assert min_set_size([3, 3, 3, 3, 5, 5, 5, 2, 2, 7]) == 2
    assert min_set_size([7, 7, 7, 7, 7, 7]) == 1
    assert min_set_size([1, 2]) == 1
    assert min_set_size([1, 9, 3, 8, 3, 8, 8, 8, 8, 8]) == 1
    try:
        min_set_size([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty arr must raise ValueError")
    assert stdlib_only()
    print("heap-32.v1 OK")


if __name__ == "__main__":
    main()
