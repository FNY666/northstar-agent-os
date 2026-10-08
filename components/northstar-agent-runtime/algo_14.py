"""Interpolation search.

Estimates the probe position from the value distribution of a sorted,
uniformly distributed list, rather than always probing the middle.
Requires ``arr`` to be sorted ascending; works best on uniform data.

Complexity: time O(log log n) average on uniform data, O(n) worst case;
space O(1), where n = len(arr).
"""

from typing import Any, List

ALGO_14_VERSION = "algo-14.v1"

_STDLIB = frozenset({"typing"})


def interpolation_search(arr: List[Any], target: Any) -> int:
    """Return the index of ``target`` in sorted uniform ``arr``, or -1."""
    lo, hi = 0, len(arr) - 1
    while lo <= hi and arr[lo] <= target <= arr[hi]:
        if arr[lo] == arr[hi]:
            return lo if arr[lo] == target else -1
        pos = lo + ((target - arr[lo]) * (hi - lo)) // (arr[hi] - arr[lo])
        if arr[pos] == target:
            return pos
        elif arr[pos] < target:
            lo = pos + 1
        else:
            hi = pos - 1
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
    arr = list(range(0, 100, 2))
    assert interpolation_search(arr, 0) == 0
    assert interpolation_search(arr, 50) == 25
    assert interpolation_search(arr, 98) == 49
    assert interpolation_search(arr, 51) == -1
    assert interpolation_search(arr, 200) == -1
    assert interpolation_search([], 1) == -1
    assert interpolation_search([9], 9) == 0
    assert interpolation_search([9], 3) == -1
    assert interpolation_search([5, 5, 5, 5], 5) == 0
    stdlib_only()
    print("algo-14 OK")


if __name__ == "__main__":
    main()
