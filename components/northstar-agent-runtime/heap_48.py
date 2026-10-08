"""Find the Kth Smallest Sum of a Matrix With Sorted Rows: k-th smallest sum picking one element per row IS: min-heap over the index grid IS NOT: enumerating all sums then sorting"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-48.v1"

def _req_inputs(matrix, k):
    if not isinstance(matrix, list) or not matrix or not isinstance(matrix[0], list):
        raise ValueError("matrix must be a non-empty 2D list")
    w = len(matrix[0])
    out = []
    for i, row in enumerate(matrix):
        if not isinstance(row, list) or len(row) != w or not row:
            raise ValueError(f"row {i} must be a non-empty list of length {w}")
        for v in row:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError("matrix must contain numbers")
        out.append(list(row))
    total = w ** len(out)
    if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= total:
        raise ValueError("k out of range")
    return out, k


def kth_smallest_sum(matrix, k):
    """Return the k-th smallest sum (1-based).

    Fail-closed: bad input raises :class:`ValueError`.
    """
    matrix, k = _req_inputs(matrix, k)
    n = len(matrix)
    start = tuple([0] * n)
    heap = [(sum(row[0] for row in matrix), start)]
    seen = {start}
    for _ in range(k - 1):
        s, idx = heapq.heappop(heap)
        for i in range(n):
            if idx[i] + 1 < len(matrix[i]):
                nxt = list(idx)
                nxt[i] += 1
                t = tuple(nxt)
                if t not in seen:
                    seen.add(t)
                    heapq.heappush(heap, (s - matrix[i][idx[i]] + matrix[i][nxt[i]], t))
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
    assert kth_smallest_sum([[1, 3, 11], [2, 4, 6]], 5) == 7
    assert kth_smallest_sum([[1, 3, 11], [2, 4, 6]], 9) == 17
    assert kth_smallest_sum([[1, 10, 10], [1, 4, 5], [2, 3, 6]], 7) == 9
    assert kth_smallest_sum([[5]], 1) == 5
    try:
        kth_smallest_sum([[1], [2]], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("k out of range must raise ValueError")
    assert stdlib_only()
    print("heap-48.v1 OK")


if __name__ == "__main__":
    main()
