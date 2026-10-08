"""psum_28: Alternating Prefix Sum

+/- prefix signs answer alternating range sums in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_28_VERSION = "psum-28.v1"


def build(a):
    p = [0]
    s = 1
    for x in a:
        p.append(p[-1] + s * x)
        s = -s
    return p


def alt_sum(p, l, r):
    """a[l]-a[l+1]+a[l+2]... over [l..r]."""
    v = p[r + 1] - p[l]
    return v if l % 2 == 0 else -v

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
    p = build([1, 2, 3, 4])
    assert p == [0, 1, -1, 2, -2]
    assert alt_sum(p, 0, 3) == -2
    assert alt_sum(p, 1, 2) == -1
    assert alt_sum(p, 0, 0) == 1
    assert stdlib_only()
    print("psum_28 OK")


if __name__ == "__main__":
    main()
