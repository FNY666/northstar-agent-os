"""K-th Smallest Prime Fraction: k-th smallest fraction arr[i]/arr[j] for i < j IS: min-heap over fraction numerators per denominator IS NOT: enumerating all fractions then sorting"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-26.v1"

def _req_inputs(arr, k):
    if not isinstance(arr, list) or len(arr) < 2:
        raise ValueError("arr must be a list of at least 2 numbers")
    for i, x in enumerate(arr):
        if isinstance(x, bool) or not isinstance(x, (int, float)) or x <= 0:
            raise ValueError(f"arr[{i}] must be a positive number")
    if any(arr[i] >= arr[i + 1] for i in range(len(arr) - 1)):
        raise ValueError("arr must be strictly increasing")
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    total = len(arr) * (len(arr) - 1) // 2
    if not 1 <= k <= total:
        raise ValueError("k out of range")
    return list(arr), k


def kth_smallest_prime_fraction(arr, k):
    """Return the k-th smallest fraction as ``[numerator, denominator]``.

    Fail-closed: bad input raises :class:`ValueError`.
    """
    arr, k = _req_inputs(arr, k)
    n = len(arr)
    heap = [(arr[0] / arr[j], 0, j) for j in range(1, n)]
    heapq.heapify(heap)
    for _ in range(k - 1):
        _, i, j = heapq.heappop(heap)
        if i + 1 < j:
            heapq.heappush(heap, (arr[i + 1] / arr[j], i + 1, j))
    _, i, j = heap[0]
    return [arr[i], arr[j]]

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
    assert kth_smallest_prime_fraction([1, 2, 3, 5], 3) == [2, 5]
    assert kth_smallest_prime_fraction([1, 7], 1) == [1, 7]
    assert kth_smallest_prime_fraction([1, 2, 3, 5], 1) == [1, 5]
    try:
        kth_smallest_prime_fraction([5, 1], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("non-increasing arr must raise ValueError")
    assert stdlib_only()
    print("heap-26.v1 OK")


if __name__ == "__main__":
    main()
