"""Counting sort: count occurrences of each value, then emit in order.

Only valid for non-negative integers: a ``ValueError`` is raised on any
negative input. Builds a frequency table of size ``max(arr) + 1`` and
writes each value back as many times as it occurred.

Time complexity: O(n + k) where k = max(arr).
Space complexity: O(n + k).
Stable: yes (equal values are emitted contiguously in input order).
"""

import ast
import sys
from typing import List

ALGO_07_VERSION = "algo-07.v1"


def counting_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the non-negative ints of ``arr`` sorted ascending."""
    a = list(arr)
    if not a:
        return []
    for v in a:
        if v < 0:
            raise ValueError("counting_sort requires non-negative ints, got %r" % (v,))
    top = max(a)
    counts = [0] * (top + 1)
    for v in a:
        counts[v] += 1
    out: List[int] = []
    for value, c in enumerate(counts):
        out.extend([value] * c)
    return out


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert counting_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert counting_sort([]) == []
    assert counting_sort([7]) == [7]
    assert counting_sort([0, 0, 0]) == [0, 0, 0]
    assert counting_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert counting_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    try:
        counting_sort([1, -2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on negative input")
    src = [3, 1, 2]
    assert counting_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-07 OK")


if __name__ == "__main__":
    main()
