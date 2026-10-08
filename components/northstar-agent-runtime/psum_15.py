"""psum_15: Range Product With Zeros

Zero-count prefix plus nonzero-product prefix handles zeros exactly.

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_15_VERSION = "psum-15.v1"


def build(a):
    p = [1]
    z = [0]
    for x in a:
        z.append(z[-1] + (1 if x == 0 else 0))
        p.append(p[-1] * (x if x != 0 else 1))
    return p, z


def range_prod(pz, l, r):
    p, z = pz
    if z[r + 1] - z[l] > 0:
        return 0
    return p[r + 1] // p[l]

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
    pz = build([2, 0, 3, 4])
    assert range_prod(pz, 0, 3) == 0
    assert range_prod(pz, 2, 3) == 12
    assert range_prod(pz, 0, 0) == 2
    pz = build([2, 3])
    assert range_prod(pz, 0, 1) == 6
    assert stdlib_only()
    print("psum_15 OK")


if __name__ == "__main__":
    main()
