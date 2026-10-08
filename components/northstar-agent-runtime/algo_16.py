"""Ternary search.

Splits the sorted list into three parts with two midpoints (m1, m2) and
discards the third that cannot contain the target. Requires ``arr`` to be
sorted ascending.

Complexity: time O(log3 n) ~ O(log n), space O(1), where n = len(arr).
"""

from typing import Any, List

ALGO_16_VERSION = "algo-16.v1"

_STDLIB = frozenset({"typing"})


def ternary_search(arr: List[Any], target: Any) -> int:
    """Return the index of ``target`` in sorted ``arr``, or -1 if absent."""
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        third = (hi - lo) // 3
        m1 = lo + third
        m2 = hi - third
        if arr[m1] == target:
            return m1
        if arr[m2] == target:
            return m2
        if target < arr[m1]:
            hi = m1 - 1
        elif target > arr[m2]:
            lo = m2 + 1
        else:
            lo = m1 + 1
            hi = m2 - 1
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
    arr = [1, 2, 4, 8, 16, 32, 64, 128]
    assert ternary_search(arr, 1) == 0
    assert ternary_search(arr, 16) == 4
    assert ternary_search(arr, 128) == 7
    assert ternary_search(arr, 3) == -1
    assert ternary_search(arr, 200) == -1
    assert ternary_search([], 1) == -1
    assert ternary_search([7], 7) == 0
    assert ternary_search([7], 2) == -1
    stdlib_only()
    print("algo-16 OK")


if __name__ == "__main__":
    main()
