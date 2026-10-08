"""Iterative binary search.

Repeatedly halves the search interval of a sorted list until the target is
found or the interval is empty. Requires ``arr`` to be sorted ascending.

Complexity: time O(log n), space O(1), where n = len(arr).
"""

from typing import Any, List

ALGO_12_VERSION = "algo-12.v1"

_STDLIB = frozenset({"typing"})


def binary_search(arr: List[Any], target: Any) -> int:
    """Return the index of ``target`` in sorted ``arr``, or -1 if absent."""
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


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
    arr = [1, 3, 5, 7, 9, 11, 13]
    assert binary_search(arr, 1) == 0
    assert binary_search(arr, 7) == 3
    assert binary_search(arr, 13) == 6
    assert binary_search(arr, 8) == -1
    assert binary_search(arr, 0) == -1
    assert binary_search([], 5) == -1
    assert binary_search([42], 42) == 0
    assert binary_search([42], 7) == -1
    stdlib_only()
    print("algo-12 OK")


if __name__ == "__main__":
    main()
