"""lis-21: LIS via Fenwick tree.

Coordinate compression plus a max Fenwick tree, O(n log n).

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import sys
LIS_21_VERSION = "lis-21.v1"


def _check_seq(seq):
    """Validate seq is a list/tuple of numbers; return a list copy."""
    if not isinstance(seq, (list, tuple)):
        raise ValueError("seq must be a list or tuple")
    for x in seq:
        if not isinstance(x, (int, float)):
            raise ValueError("seq elements must be numbers")
    return list(seq)
def lis_fenwick(seq):
    """LIS length using a Fenwick tree over compressed coordinates."""
    a = _check_seq(seq)
    n = len(a)
    if n == 0:
        return 0
    vals = sorted(set(a))
    rank = {v: i + 1 for i, v in enumerate(vals)}
    size = len(vals) + 2
    bit = [0] * size

    def bit_update(i, v):
        while i < size:
            if v > bit[i]:
                bit[i] = v
            i += i & -i

    def bit_query(i):
        r = 0
        while i > 0:
            if bit[i] > r:
                r = bit[i]
            i -= i & -i
        return r

    for x in a:
        r = rank[x]
        bit_update(r, bit_query(r - 1) + 1)
    return bit_query(size - 1)

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
    assert lis_fenwick([10, 9, 2, 5, 3, 7, 101, 18]) == 4
    assert lis_fenwick([5, 4, 3, 2, 1]) == 1
    assert lis_fenwick([]) == 0
    assert stdlib_only()
    print("lis-21 OK")


if __name__ == "__main__":
    main()
