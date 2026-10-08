"""psum_31: Parentheses Balance (Min Prefix)

Map '(' -> +1, ')' -> -1: balanced iff total 0 and min prefix >= 0.

Time complexity: O(n) time
Space complexity: O(1)"""

import ast
import sys
PSUM_31_VERSION = "psum-31.v1"


def min_prefix(a):
    s = 0
    best = 0
    for x in a:
        s += x
        if s < best:
            best = s
    return best


def balanced(parens):
    a = [1 if c == "(" else -1 for c in parens]
    return min_prefix(a) >= 0 and sum(a) == 0

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
    assert balanced("(()())") is True
    assert balanced("())(()") is False
    assert balanced("") is True
    assert balanced("(((") is False
    assert min_prefix([1, -2, 1]) == -1
    assert stdlib_only()
    print("psum_31 OK")


if __name__ == "__main__":
    main()
