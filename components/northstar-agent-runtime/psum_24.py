"""psum_24: Total Variation Prefix

Prefix of |a[i]-a[i-1]| answers range wiggle in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_24_VERSION = "psum-24.v1"


def build(a):
    p = [0]
    for i in range(1, len(a)):
        p.append(p[-1] + abs(a[i] - a[i - 1]))
    return p


def variation(p, l, r):
    return p[r] - p[l]

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
    p = build([1, 4, 2, 8])
    assert p == [0, 3, 5, 11]
    assert variation(p, 0, 3) == 11
    assert variation(p, 1, 2) == 2
    assert variation(p, 0, 0) == 0
    assert stdlib_only()
    print("psum_24 OK")


if __name__ == "__main__":
    main()
