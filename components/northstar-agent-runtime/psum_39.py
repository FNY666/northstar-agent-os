"""psum_39: Prefix Sum Mod 1e9+7

Large-number prefix sums kept exact under the classic prime modulus.

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_39_VERSION = "psum-39.v1"


MOD = 1000000007


def build(a):
    p = [0]
    for x in a:
        p.append((p[-1] + x) % MOD)
    return p


def range_sum(p, l, r):
    return (p[r + 1] - p[l]) % MOD

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
    p = build([10 ** 9, 10 ** 9])
    assert p[2] == (2 * 10 ** 9) % 1000000007
    assert range_sum(p, 0, 1) == (2 * 10 ** 9) % 1000000007
    p = build([5])
    assert range_sum(p, 0, 0) == 5
    assert build([]) == [0]
    assert stdlib_only()
    print("psum_39 OK")


if __name__ == "__main__":
    main()
