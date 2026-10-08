"""psum_50: Prefix Product Mod Prime

Modular inverses make range products O(1) under a prime modulus (no zeros).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_50_VERSION = "psum-50.v1"


MOD = 1000000007


def build(a):
    p = [1]
    for x in a:
        p.append(p[-1] * x % MOD)
    return p


def range_prod(p, l, r):
    """Product of a[l..r] mod MOD; requires no zero in range."""
    return p[r + 1] * pow(p[l], MOD - 2, MOD) % MOD

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
    p = build([2, 3, 4])
    assert p == [1, 2, 6, 24]
    assert range_prod(p, 0, 2) == 24
    assert range_prod(p, 1, 2) == 12
    assert range_prod(p, 0, 0) == 2
    assert range_prod(p, 2, 2) == 4
    assert stdlib_only()
    print("psum_50 OK")


if __name__ == "__main__":
    main()
