"""psum_34: Second-Order Prefix Sum

Prefix of the prefix: answers sums of prefix sums in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_34_VERSION = "psum-34.v1"


def build(a):
    p1 = [0]
    for x in a:
        p1.append(p1[-1] + x)
    p2 = [0]
    for x in p1[1:]:
        p2.append(p2[-1] + x)
    return p2


def prefix_of_prefix(p2, i):
    """Sum of prefix sums P[1..i+1]."""
    return p2[i + 1]

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
    p2 = build([1, 2, 3])
    assert p2 == [0, 1, 4, 10]
    assert prefix_of_prefix(p2, 2) == 10
    assert prefix_of_prefix(p2, 0) == 1
    assert build([]) == [0]
    assert stdlib_only()
    print("psum_34 OK")


if __name__ == "__main__":
    main()
