"""psum_42: Prefix OR (From Zero)

Cumulative OR answers prefix OR queries; OR is not invertible for ranges.

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_42_VERSION = "psum-42.v1"


def build(a):
    p = [0]
    for x in a:
        p.append(p[-1] | x)
    return p


def prefix_or(p, i):
    """OR of a[0..i]."""
    return p[i + 1]

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
    p = build([1, 2, 4])
    assert p == [0, 1, 3, 7]
    assert prefix_or(p, 2) == 7
    assert prefix_or(p, 0) == 1
    assert prefix_or(p, 1) == 3
    assert stdlib_only()
    print("psum_42 OK")


if __name__ == "__main__":
    main()
