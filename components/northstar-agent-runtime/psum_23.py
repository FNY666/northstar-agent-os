"""psum_23: Suffix Sums

Right-to-left accumulation answers every suffix sum in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_23_VERSION = "psum-23.v1"


def build(a):
    n = len(a)
    s = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        s[i] = s[i + 1] + a[i]
    return s


def suffix(s, i):
    """Sum of a[i:]."""
    return s[i]

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
    s = build([1, 2, 3, 4])
    assert s == [10, 9, 7, 4, 0]
    assert suffix(s, 2) == 7
    assert suffix(s, 0) == 10
    assert suffix(s, 4) == 0
    assert stdlib_only()
    print("psum_23 OK")


if __name__ == "__main__":
    main()
