"""intv_17: Check every integer in [left, right] is covered (is_covered).

Merge then walk; the union must contain the whole query range.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_17 = "intv-17.v1"


def is_covered(ranges, left, right):
    """True when [left, right] is fully covered by ``ranges``."""
    ivs = sorted(ranges, key=lambda x: x[0])
    cur = left
    for s, e in ivs:
        if s > cur:
            return False
        if e >= cur:
            cur = e + 1
        if cur > right:
            return True
    return cur > right

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
    assert is_covered([(1, 2), (3, 4), (5, 6)], 2, 5) is True
    assert is_covered([(1, 10), (10, 20)], 21, 21) is False
    assert is_covered([], 1, 1) is False
    assert is_covered([(1, 50)], 1, 50) is True
    assert is_covered([(1, 2), (4, 5)], 1, 5) is False
    assert stdlib_only()
    print("intv_17 OK")


if __name__ == "__main__":
    main()
