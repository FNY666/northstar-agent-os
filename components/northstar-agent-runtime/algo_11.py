"""Linear search.

Scans the sequence left to right and returns the index of the first element
equal to ``target``. Returns -1 when the target is absent.

Complexity: time O(n), space O(1), where n = len(arr).
"""

from typing import Any, List

ALGO_11_VERSION = "algo-11.v1"

_STDLIB = frozenset({"typing"})


def linear_search(arr: List[Any], target: Any) -> int:
    """Return the index of ``target`` in ``arr``, or -1 if not present."""
    for i, value in enumerate(arr):
        if value == target:
            return i
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
    assert linear_search([5, 3, 8, 1], 8) == 2
    assert linear_search([5, 3, 8, 1], 5) == 0
    assert linear_search([5, 3, 8, 1], 1) == 3
    assert linear_search([5, 3, 8, 1], 99) == -1
    assert linear_search([], 1) == -1
    assert linear_search([7], 7) == 0
    assert linear_search([7], 8) == -1
    stdlib_only()
    print("algo-11 OK")


if __name__ == "__main__":
    main()
