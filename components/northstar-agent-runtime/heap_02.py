"""Kth Smallest Element: return the k-th smallest element of a list via a heap IS: heapq.nsmallest under the hood IS NOT: a full sort or an order-statistic tree"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-02.v1"

def _req_nums(value, name):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name} must be a non-empty list")
    for x in value:
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            raise ValueError(f"{name} must contain only numbers")
    return list(value)


def _req_k(k, n):
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if not 1 <= k <= n:
        raise ValueError("k must satisfy 1 <= k <= len(nums)")
    return k


def kth_smallest(nums, k):
    """Return the k-th smallest element of ``nums``.

    Fail-closed: ``nums`` must be a non-empty list of numbers and
    ``1 <= k <= len(nums)``, otherwise :class:`ValueError`.
    """
    nums = _req_nums(nums, "nums")
    k = _req_k(k, len(nums))
    return heapq.nsmallest(k, nums)[-1]

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
    assert kth_smallest([3, 2, 1, 5, 6, 4], 2) == 2
    assert kth_smallest([3, 2, 3, 1, 2, 4, 5, 5, 6], 4) == 3
    assert kth_smallest([1], 1) == 1
    assert kth_smallest([-1, -5, 0, 2], 1) == -5
    try:
        kth_smallest("nope", 1)
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    try:
        kth_smallest([1], 2)
    except ValueError:
        pass
    else:
        raise AssertionError("k > len must raise ValueError")
    assert stdlib_only()
    print("heap-02.v1 OK")


if __name__ == "__main__":
    main()
