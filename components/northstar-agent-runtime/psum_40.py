"""psum_40: Range Add + Range Sum (Dual BIT)

Two Fenwick trees simulate a difference array with O(log n) range add/sum.

Time complexity: O(log n) update/query
Space complexity: O(n)"""

import ast
import sys
PSUM_40_VERSION = "psum-40.v1"


def build(n):
    return [0] * (n + 2), [0] * (n + 2)


def _add(b, i, v):
    while i < len(b):
        b[i] += v
        i += i & -i


def range_add(bit, l, r, v):
    """Add v to a[l..r] (0-indexed)."""
    b1, b2 = bit
    _add(b1, l + 1, v)
    _add(b1, r + 2, -v)
    _add(b2, l + 1, v * l)
    _add(b2, r + 2, -v * (r + 1))


def _sum(b, i):
    s = 0
    while i > 0:
        s += b[i]
        i -= i & -i
    return s


def prefix_sum(bit, i):
    b1, b2 = bit
    return _sum(b1, i + 1) * (i + 1) - _sum(b2, i + 1)


def range_sum(bit, l, r):
    return prefix_sum(bit, r) - (prefix_sum(bit, l - 1) if l else 0)

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
    bit = build(5)
    range_add(bit, 1, 3, 2)
    assert range_sum(bit, 0, 4) == 6
    assert range_sum(bit, 1, 3) == 6
    assert range_sum(bit, 0, 0) == 0
    range_add(bit, 0, 4, 1)
    assert range_sum(bit, 0, 4) == 11
    assert stdlib_only()
    print("psum_40 OK")


if __name__ == "__main__":
    main()
