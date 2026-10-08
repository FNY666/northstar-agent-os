"""Jump search.

Jumps ahead in fixed blocks of size sqrt(n) over a sorted list to find the
block that could contain the target, then scans that block linearly.
Requires ``arr`` to be sorted ascending.

Complexity: time O(sqrt(n)), space O(1), where n = len(arr).
"""

import math
from typing import Any, List

ALGO_13_VERSION = "algo-13.v1"

_STDLIB = frozenset({"typing", "math"})


def jump_search(arr: List[Any], target: Any) -> int:
    """Return the index of ``target`` in sorted ``arr``, or -1 if absent."""
    n = len(arr)
    if n == 0:
        return -1
    block = max(1, int(math.sqrt(n)))
    prev, step = 0, block
    while prev < n and arr[min(step, n) - 1] < target:
        prev = step
        step += block
        if prev >= n:
            return -1
    for i in range(prev, min(step, n)):
        if arr[i] == target:
            return i
        if arr[i] > target:
            return -1
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
    arr = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    assert jump_search(arr, 2) == 0
    assert jump_search(arr, 10) == 4
    assert jump_search(arr, 20) == 9
    assert jump_search(arr, 7) == -1
    assert jump_search(arr, 21) == -1
    assert jump_search([], 3) == -1
    assert jump_search([5], 5) == 0
    assert jump_search([5], 6) == -1
    stdlib_only()
    print("algo-13 OK")


if __name__ == "__main__":
    main()
