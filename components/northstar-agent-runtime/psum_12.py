"""psum_12: Subarrays Divisible by K

Remainders of prefix sums: equal remainders mark divisible subarrays.

Time complexity: O(n) time
Space complexity: O(k)"""

import ast
import sys
PSUM_12_VERSION = "psum-12.v1"


def count(a, k):
    seen = {0: 1}
    s = 0
    c = 0
    for x in a:
        s = (s + x) % k
        c += seen.get(s, 0)
        seen[s] = seen.get(s, 0) + 1
    return c

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
    assert count([4, 5, 0, -2, -3, 1], 5) == 7
    assert count([5], 5) == 1
    assert count([5], 9) == 0
    assert count([0, 0], 3) == 3
    assert stdlib_only()
    print("psum_12 OK")


if __name__ == "__main__":
    main()
