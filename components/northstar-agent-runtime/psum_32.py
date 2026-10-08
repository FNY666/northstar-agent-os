"""psum_32: Strictly Increasing Prefix Sums

Prefix totals strictly increase iff every element is positive.

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
PSUM_32_VERSION = "psum-32.v1"


def is_increasing(a):
    s = 0
    prev = None
    for x in a:
        s += x
        if prev is not None and s <= prev:
            return False
        prev = s
    return True

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
    assert is_increasing([1, 2, 3]) is True
    assert is_increasing([2, -1, 3]) is False
    assert is_increasing([5]) is True
    assert is_increasing([]) is True
    assert is_increasing([1, 0]) is False
    assert stdlib_only()
    print("psum_32 OK")


if __name__ == "__main__":
    main()
