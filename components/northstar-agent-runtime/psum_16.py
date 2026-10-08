"""psum_16: Prefix AND (From Zero)

Cumulative AND answers prefix AND queries; AND is not invertible for ranges.

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_16_VERSION = "psum-16.v1"


def build(a):
    p = [~0]
    for x in a:
        p.append(p[-1] & x)
    return p


def prefix_and(p, i):
    """AND of a[0..i]."""
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
    p = build([12, 10, 9])
    assert prefix_and(p, 0) == 12
    assert prefix_and(p, 1) == 8
    assert prefix_and(p, 2) == 8
    p = build([7])
    assert prefix_and(p, 0) == 7
    assert stdlib_only()
    print("psum_16 OK")


if __name__ == "__main__":
    main()
