"""psum_30: Maximum Prefix Sum

Largest prefix total; the best you can do starting from index 0.

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
PSUM_30_VERSION = "psum-30.v1"


def max_prefix(a):
    s = 0
    best = 0
    for x in a:
        s += x
        if s > best:
            best = s
    return best

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
    assert max_prefix([-2, 1, -3, 4, -1, 2, 1, -5, 4]) == 2
    assert max_prefix([1, 2, 3]) == 6
    assert max_prefix([-5, -1]) == 0
    assert max_prefix([]) == 0
    assert stdlib_only()
    print("psum_30 OK")


if __name__ == "__main__":
    main()
