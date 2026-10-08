"""psum_29: Range Flip (XOR Difference)

XOR difference array toggles ranges in O(1); materialize with prefix XOR.

Time complexity: O(1) update, O(n) materialize
Space complexity: O(n)"""

import ast
import sys
PSUM_29_VERSION = "psum-29.v1"


def build(n):
    return [0] * (n + 1)


def flip(d, l, r):
    d[l] ^= 1
    d[r + 1] ^= 1


def materialize(d):
    out = []
    cur = 0
    for x in d[:-1]:
        cur ^= x
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
    flip(d, 1, 3)
    assert materialize(d) == [0, 1, 1, 1, 0]
    flip(d, 2, 4)
    assert materialize(d) == [0, 1, 0, 0, 1]
    d = build(1)
    assert materialize(d) == [0]
    assert stdlib_only()
    print("psum_29 OK")


if __name__ == "__main__":
    main()
