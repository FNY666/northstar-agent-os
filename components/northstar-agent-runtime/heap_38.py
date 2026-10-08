"""Merge K Sorted Arrays: merge several sorted arrays into one sorted array IS: min-heap seeded with each array head IS NOT: concatenating then sorting"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-38.v1"

def _req_arrays(value):
    if not isinstance(value, list):
        raise ValueError("arrays must be a list of lists")
    out = []
    for i, sub in enumerate(value):
        if not isinstance(sub, list):
            raise ValueError(f"arrays[{i}] must be a list")
        out.append(list(sub))
    return out


def merge_k_sorted_arrays(arrays):
    """Merge sorted arrays into a single sorted list.

    Fail-closed: input must be a list of lists, else :class:`ValueError`.
    """
    arrays = _req_arrays(arrays)
    heap = [(row[0], i, 0) for i, row in enumerate(arrays) if row]
    heapq.heapify(heap)
    out = []
    while heap:
        val, i, j = heapq.heappop(heap)
        out.append(val)
        if j + 1 < len(arrays[i]):
            heapq.heappush(heap, (arrays[i][j + 1], i, j + 1))
    return out

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
    assert merge_k_sorted_arrays([[1, 4, 5], [1, 3, 4], [2, 6]]) == [1, 1, 2, 3, 4, 4, 5, 6]
    assert merge_k_sorted_arrays([]) == []
    assert merge_k_sorted_arrays([[], []]) == []
    assert merge_k_sorted_arrays([[3, 5], [1]]) == [1, 3, 5]
    try:
        merge_k_sorted_arrays("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("heap-38.v1 OK")


if __name__ == "__main__":
    main()
