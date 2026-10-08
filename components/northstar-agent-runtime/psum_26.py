"""psum_26: Weighted Prefix Sum

Sum of i*x[i] prefixes support weighted range queries in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_26_VERSION = "psum-26.v1"


def build(a):
    p = [0]
    w = [0]
    for i, x in enumerate(a):
        p.append(p[-1] + x)
        w.append(w[-1] + i * x)
    return p, w


def weighted(pw, l, r):
    p, w = pw
    return w[r + 1] - w[l]

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
    pw = build([1, 2, 3])
    assert weighted(pw, 0, 2) == 8
    assert weighted(pw, 1, 2) == 8
    assert weighted(pw, 0, 0) == 0
    assert weighted(pw, 2, 2) == 6
    assert stdlib_only()
    print("psum_26 OK")


if __name__ == "__main__":
    main()
