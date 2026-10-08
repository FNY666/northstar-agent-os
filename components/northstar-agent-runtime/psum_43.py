"""psum_43: Threshold Count Prefix

Indicator prefix counts elements greater than t in any range in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_43_VERSION = "psum-43.v1"


def build(a, t):
    p = [0]
    for x in a:
        p.append(p[-1] + (1 if x > t else 0))
    return p


def count_gt(p, l, r):
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
    p = build([3, 1, 4, 1, 5, 9, 2, 6], 4)
    assert p == [0, 0, 0, 0, 0, 1, 2, 2, 3]
    assert count_gt(p, 0, 7) == 3
    assert count_gt(p, 4, 7) == 3
    assert count_gt(p, 0, 3) == 0
    assert stdlib_only()
    print("psum_43 OK")


if __name__ == "__main__":
    main()
