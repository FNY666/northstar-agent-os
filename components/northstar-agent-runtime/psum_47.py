"""psum_47: Subarray XOR Equals Target (Count)

Prefix-XOR frequency map counts subarrays with XOR == target in one pass.

Time complexity: O(n) time
Space complexity: O(n)"""

import ast
import sys
PSUM_47_VERSION = "psum-47.v1"


def count(a, t):
    seen = {0: 1}
    x = 0
    c = 0
    for v in a:
        x ^= v
        c += seen.get(x ^ t, 0)
        seen[x] = seen.get(x, 0) + 1
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
    assert count([4, 2, 2, 6, 4], 6) == 4
    assert count([5, 2, 3], 5) == 1
    assert count([], 1) == 0
    assert count([1, 1], 0) == 1
    assert stdlib_only()
    print("psum_47 OK")


if __name__ == "__main__":
    main()
