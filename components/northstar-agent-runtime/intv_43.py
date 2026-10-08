"""intv_43: Minimum taps to water the garden (min_taps).

Convert taps to intervals; greedy-cover [0, n].

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_43 = "intv-43.v1"


def min_taps(n, ranges):
    """Min taps watering [0, n]; -1 when impossible."""
    ivs = []
    for i, r in enumerate(ranges):
        if r > 0:
            ivs.append((i - r, i + r))
    ivs.sort()
    used = 0
    cur_end = 0
    i = 0
    m = len(ivs)
    while cur_end < n:
        best = cur_end
        while i < m and ivs[i][0] <= cur_end:
            if ivs[i][1] > best:
                best = ivs[i][1]
            i += 1
        if best == cur_end:
            return -1
        used += 1
        cur_end = best
    return used

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
    assert min_taps(5, [3, 4, 1, 1, 0, 0]) == 1
    assert min_taps(3, [0, 0, 0, 0]) == -1
    assert min_taps(7, [1, 2, 1, 0, 2, 1, 0, 1]) == 3
    assert min_taps(1, [1, 1]) == 1
    assert min_taps(0, [0]) == 0
    assert stdlib_only()
    print("intv_43 OK")


if __name__ == "__main__":
    main()
