"""psum_01: Range Sum Query (1D)

Prefix sums turn every range-sum query into O(1): sum(l..r) = P[r+1] - P[l].

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_01_VERSION = "psum-01.v1"


def build(a):
    """Return prefix array P with P[0]=0 and P[i+1]=sum(a[:i+1])."""
    p = [0]
    for x in a:
        p.append(p[-1] + x)
    return p


def range_sum(p, l, r):
    """Inclusive range sum a[l..r] from prefix array p."""
    if l > r:
        return 0
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
    p = build([1, 2, 3, 4, 5])
    assert p == [0, 1, 3, 6, 10, 15]
    assert range_sum(p, 1, 3) == 9
    assert range_sum(p, 0, 4) == 15
    assert range_sum(p, 2, 2) == 3
    assert range_sum(p, 3, 1) == 0
    assert build([]) == [0]
    assert stdlib_only()
    print("psum_01 OK")


if __name__ == "__main__":
    main()
