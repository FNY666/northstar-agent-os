"""psum_37: Circular Array Range Sum

Duplicate-free trick: wrap-around range = total - middle, all from one prefix.

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_37_VERSION = "psum-37.v1"


def build(a):
    p = [0]
    for x in a:
        p.append(p[-1] + x)
    return p


def circ(p, l, r):
    """Sum of a[l..r] on a circular array (l may exceed r)."""
    n = len(p) - 1
    if l <= r:
        return p[r + 1] - p[l]
    return p[n] - p[l] + p[r + 1]

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
    p = build([1, 2, 3, 4, 5])
    assert circ(p, 3, 1) == 12
    assert circ(p, 1, 3) == 9
    assert circ(p, 0, 4) == 15
    assert circ(p, 4, 4) == 5
    assert stdlib_only()
    print("psum_37 OK")


if __name__ == "__main__":
    main()
