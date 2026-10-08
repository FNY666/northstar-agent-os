"""psum_03: Prefix Sum With Point Update

Point update then rebuild keeps queries O(1); rebuild is O(n).

Time complexity: O(n) update, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_03_VERSION = "psum-03.v1"


def build(a):
    p = [0]
    for x in a:
        p.append(p[-1] + x)
    return p


def point_update(a, idx, val):
    """Set a[idx]=val and return (new_a, new_prefix)."""
    a = list(a)
    a[idx] = val
    return a, build(a)


def range_sum(p, l, r):
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
    a, p = point_update([1, 2, 3], 1, 10)
    assert a == [1, 10, 3]
    assert range_sum(p, 0, 2) == 14
    a, p = point_update(a, 0, 0)
    assert range_sum(p, 0, 2) == 13
    assert range_sum(p, 1, 1) == 10
    assert stdlib_only()
    print("psum_03 OK")


if __name__ == "__main__":
    main()
