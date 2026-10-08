"""greedy_45: Reduce array size to the half.

Remove the most frequent values first; greedy on frequencies is optimal.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_45_VERSION = "greedy-45.v1"


def min_set_size(arr):
    """Return the min number of distinct values to remove to halve the array."""
    from collections import Counter
    counts = sorted(Counter(arr).values(), reverse=True)
    removed = 0
    target = len(arr) / 2
    k = 0
    for c in counts:
        removed += c
        k += 1
        if removed >= target:
            break
    return k

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
    assert min_set_size([3, 3, 3, 3, 5, 5, 5, 2, 2, 7]) == 2
    assert min_set_size([7, 7, 7, 7, 7, 7]) == 1
    assert min_set_size([1, 9]) == 1
    assert min_set_size([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) == 5
    assert stdlib_only()
    print("greedy_45 OK")


if __name__ == "__main__":
    main()
