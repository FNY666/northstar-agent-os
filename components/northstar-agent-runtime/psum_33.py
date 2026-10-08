"""psum_33: Range XOR Update, Point Query

XOR difference array: range XOR updates in O(1), point query by prefix XOR.

Time complexity: O(1) update, O(n) query
Space complexity: O(n)"""

import ast
import sys
PSUM_33_VERSION = "psum-33.v1"


def build(n):
    return [0] * (n + 1)


def range_xor(d, l, r, v):
    d[l] ^= v
    d[r + 1] ^= v


def point(d, i):
    x = 0
    for j in range(i + 1):
        x ^= d[j]
    return x

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
    d = build(5)
    range_xor(d, 1, 3, 7)
    assert point(d, 0) == 0
    assert point(d, 2) == 7
    assert point(d, 4) == 0
    range_xor(d, 2, 2, 7)
    assert point(d, 2) == 0
    assert stdlib_only()
    print("psum_33 OK")


if __name__ == "__main__":
    main()
