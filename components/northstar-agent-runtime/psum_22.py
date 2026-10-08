"""psum_22: Prefix Parity (Even Counts)

Indicator prefix counts even numbers in any range in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_22_VERSION = "psum-22.v1"


def build(a):
    p = [0]
    for x in a:
        p.append(p[-1] + (1 if x % 2 == 0 else 0))
    return p


def evens(p, l, r):
    return p[r + 1] - p[l]

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
    p = build([1, 2, 3, 4, 5, 6])
    assert p == [0, 0, 1, 1, 2, 2, 3]
    assert evens(p, 0, 5) == 3
    assert evens(p, 2, 4) == 1
    assert evens(p, 0, 0) == 0
    assert stdlib_only()
    print("psum_22 OK")


if __name__ == "__main__":
    main()
