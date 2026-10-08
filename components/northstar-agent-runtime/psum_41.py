"""psum_41: Telescoping Sum

Prefix of a difference array recovers the original sequence exactly.

Time complexity: O(n) time
Space complexity: O(n)"""

import ast
import sys
PSUM_41_VERSION = "psum-41.v1"


def tele(d):
    """Recover a from its difference array d (d[0] = a[0])."""
    out = []
    s = 0
    for x in d:
        s += x
        out.append(s)
    return out

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
    assert tele([1, 2, 1, 3]) == [1, 3, 4, 7]
    assert tele([5]) == [5]
    assert tele([]) == []
    assert tele([0, 0, 4]) == [0, 0, 4]
    assert stdlib_only()
    print("psum_41 OK")


if __name__ == "__main__":
    main()
