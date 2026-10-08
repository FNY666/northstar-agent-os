"""Exponential search.

Finds a range [bound/2, bound] that may contain the target by doubling the
bound (1, 2, 4, ...), then runs binary search inside that range. Shines when
the target is near the front of a long sorted list. Requires ``arr`` sorted
ascending.

Complexity: time O(log i) where i is the target's index (O(log n) worst
case), space O(1).
"""

from typing import Any, List

ALGO_15_VERSION = "algo-15.v1"

_STDLIB = frozenset({"typing"})


def _binary_search_range(arr: List[Any], target: Any, lo: int, hi: int) -> int:
    """Binary search restricted to the closed index range [lo, hi]."""
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def exponential_search(arr: List[Any], target: Any) -> int:
    """Return the index of ``target`` in sorted ``arr``, or -1 if absent."""
    n = len(arr)
    if n == 0:
        return -1
    if arr[0] == target:
        return 0
    bound = 1
    while bound < n and arr[bound] <= target:
        bound *= 2
    return _binary_search_range(arr, target, bound // 2, min(bound, n - 1))


def stdlib_only() -> None:
    """Parse this file with ast; assert all module-level imports are used stdlib."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                imported.setdefault(top, set()).add((alias.asname or top).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                top = node.module.split(".")[0]
                for alias in node.names:
                    imported.setdefault(top, set()).add(alias.asname or alias.name)
    assert set(imported) <= _STDLIB, f"non-stdlib imports: {set(imported) - _STDLIB}"
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for mod, names in imported.items():
        for name in names:
            assert name in used, f"imported but unused: {name} (from {mod})"


def main() -> None:
    arr = [3, 6, 9, 12, 15, 18, 21, 24, 27, 30]
    assert exponential_search(arr, 3) == 0
    assert exponential_search(arr, 15) == 4
    assert exponential_search(arr, 30) == 9
    assert exponential_search(arr, 16) == -1
    assert exponential_search(arr, 31) == -1
    assert exponential_search([], 3) == -1
    assert exponential_search([11], 11) == 0
    assert exponential_search([11], 5) == -1
    stdlib_only()
    print("algo-15 OK")


if __name__ == "__main__":
    main()
