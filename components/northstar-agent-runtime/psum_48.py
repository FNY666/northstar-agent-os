"""psum_48: Interval Coverage (Painting)

Difference array counts coverage; materialize marks covered cells.

Time complexity: O(1) update, O(n) materialize
Space complexity: O(n)"""

import ast
import sys
PSUM_48_VERSION = "psum-48.v1"


def build(n):
    return [0] * (n + 1)


def paint(d, l, r):
    """Cover interval [l..r]."""
    d[l] += 1
    d[r + 1] -= 1


def covered(d):
    out = []
    cur = 0
    for x in d[:-1]:
        cur += x
        out.append(1 if cur > 0 else 0)
    return out

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
    d = build(6)
    paint(d, 1, 3)
    paint(d, 2, 4)
    assert covered(d) == [0, 1, 1, 1, 1, 0]
    d = build(3)
    assert covered(d) == [0, 0, 0]
    paint(d, 0, 2)
    assert covered(d) == [1, 1, 1]
    assert stdlib_only()
    print("psum_48 OK")


if __name__ == "__main__":
    main()
