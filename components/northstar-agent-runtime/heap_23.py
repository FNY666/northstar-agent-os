"""Kth Smallest Element in a Sorted Matrix: k-th smallest element of a row- and column-sorted matrix IS: min-heap seeded with the first row, advancing column by column IS NOT: flattening and sorting the matrix"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-23.v1"

def _req_matrix(value):
    if not isinstance(value, list) or not value or not isinstance(value[0], list):
        raise ValueError("matrix must be a non-empty 2D list")
    n = len(value)
    out = []
    for i, row in enumerate(value):
        if not isinstance(row, list) or len(row) != n:
            raise ValueError(f"matrix must be square; row {i} has wrong length")
        for v in row:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError("matrix must contain numbers")
        out.append(list(row))
    return out


def kth_smallest_matrix(matrix, k):
    """Return the k-th smallest element (1-based).

    Fail-closed: matrix must be square and ``1 <= k <= n*n``,
    else :class:`ValueError`.
    """
    matrix = _req_matrix(matrix)
    n = len(matrix)
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= n * n:
        raise ValueError("k must satisfy 1 <= k <= n*n")
    heap = [(matrix[0][c], 0, c) for c in range(n)]
    heapq.heapify(heap)
    for _ in range(k - 1):
        _, r, c = heapq.heappop(heap)
        if r + 1 < n:
            heapq.heappush(heap, (matrix[r + 1][c], r + 1, c))
    return heap[0][0]

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
    m = [[1, 5, 9], [10, 11, 13], [12, 13, 15]]
    assert kth_smallest_matrix(m, 8) == 13
    assert kth_smallest_matrix(m, 1) == 1
    assert kth_smallest_matrix(m, 9) == 15
    assert kth_smallest_matrix([[-5]], 1) == -5
    try:
        kth_smallest_matrix(m, 10)
    except ValueError:
        pass
    else:
        raise AssertionError("k > n*n must raise ValueError")
    assert stdlib_only()
    print("heap-23.v1 OK")


if __name__ == "__main__":
    main()
