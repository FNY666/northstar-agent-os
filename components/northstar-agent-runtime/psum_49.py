"""psum_49: Digit Sum Prefix

Prefix sums over digit characters answer digit-sum queries on substrings.

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_49_VERSION = "psum-49.v1"


def build(s):
    p = [0]
    for ch in s:
        p.append(p[-1] + int(ch))
    return p


def digit_sum(p, l, r):
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
    p = build("12345")
    assert p == [0, 1, 3, 6, 10, 15]
    assert digit_sum(p, 1, 3) == 9
    assert digit_sum(p, 0, 4) == 15
    assert digit_sum(p, 4, 4) == 5
    assert stdlib_only()
    print("psum_49 OK")


if __name__ == "__main__":
    main()
