"""psum_06: Difference Array (Range Add)

Range addition in O(1) via difference array; materialize with one prefix pass.

Time complexity: O(1) update, O(n) materialize
Space complexity: O(n)"""

import ast
import sys
PSUM_06_VERSION = "psum-06.v1"


def build(n):
    return [0] * (n + 1)


def range_add(d, l, r, v):
    """Add v to every element of a[l..r]."""
    d[l] += v
    d[r + 1] -= v


def materialize(d):
    out = []
    cur = 0
    for x in d[:-1]:
        cur += x
        out.append(cur)
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
    d = build(5)
    range_add(d, 1, 3, 10)
    range_add(d, 2, 4, 5)
    assert materialize(d) == [0, 10, 15, 15, 5]
    d = build(3)
    range_add(d, 0, 2, -2)
    assert materialize(d) == [-2, -2, -2]
    d = build(1)
    assert materialize(d) == [0]
    assert stdlib_only()
    print("psum_06 OK")


if __name__ == "__main__":
    main()
