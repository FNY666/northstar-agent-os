"""psum_45: Max Fixed-Window Sum

Sliding window sums are differences of prefix sums; take the max.

Time complexity: O(n) time
Space complexity: O(n)"""

import ast
import sys
PSUM_45_VERSION = "psum-45.v1"


def max_window(a, k):
    p = [0]
    for x in a:
        p.append(p[-1] + x)
    return max(p[i + k] - p[i] for i in range(len(a) - k + 1))

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
    assert max_window([1, 3, -1, -3, 5, 3, 6, 7], 3) == 16
    assert max_window([1, 2, 3], 3) == 6
    assert max_window([-1, -2, -3], 2) == -3
    assert max_window([5], 1) == 5
    assert stdlib_only()
    print("psum_45 OK")


if __name__ == "__main__":
    main()
