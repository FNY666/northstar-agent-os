"""Radix sort (base 10): sort digit by digit from least to most significant.

Each digit pass is a stable counting-style distribution into 10 buckets
(one per decimal digit). Only valid for non-negative integers: a
``ValueError`` is raised on any negative input.

Time complexity: O(d * (n + 10)) where d = number of decimal digits.
Space complexity: O(n).
Stable: yes.
"""

import ast
import sys
from typing import List

ALGO_08_VERSION = "algo-08.v1"


def radix_sort(arr: List[int]) -> List[int]:
    """Return a NEW list with the non-negative ints of ``arr`` sorted ascending."""
    a = list(arr)
    if not a:
        return []
    for v in a:
        if v < 0:
            raise ValueError("radix_sort requires non-negative ints, got %r" % (v,))
    base = 10
    exp = 1
    max_v = max(a)
    while max_v // exp > 0:
        buckets: List[List[int]] = [[] for _ in range(base)]
        for v in a:
            buckets[(v // exp) % base].append(v)
        a = [v for bucket in buckets for v in bucket]
        exp *= base
    return a


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
    assert radix_sort([170, 45, 75, 90, 802, 24, 2, 66]) == [2, 24, 45, 66, 75, 90, 170, 802]
    assert radix_sort([]) == []
    assert radix_sort([7]) == [7]
    assert radix_sort([0, 0, 5]) == [0, 0, 5]
    assert radix_sort([1, 2, 3, 4]) == [1, 2, 3, 4]
    assert radix_sort([4, 3, 2, 1]) == [1, 2, 3, 4]
    assert radix_sort([3, 1, 2, 3, 1]) == [1, 1, 2, 3, 3]
    try:
        radix_sort([1, -2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on negative input")
    src = [3, 1, 2]
    assert radix_sort(src) == [1, 2, 3] and src == [3, 1, 2]
    assert stdlib_only()
    print("algo-08 OK")


if __name__ == "__main__":
    main()
