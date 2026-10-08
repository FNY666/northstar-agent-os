"""psum_17: Running Total and Mean

One pass yields every prefix sum and its running average.

Time complexity: O(n) time
Space complexity: O(n)"""

import ast
import sys
PSUM_17_VERSION = "psum-17.v1"


def running(a):
    out = []
    s = 0
    for i, x in enumerate(a, 1):
        s += x
        out.append((s, s / i))
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
    assert running([1, 2, 3]) == [(1, 1.0), (3, 1.5), (6, 2.0)]
    assert running([]) == []
    assert running([10]) == [(10, 10.0)]
    assert running([2, 2]) == [(2, 2.0), (4, 2.0)]
    assert stdlib_only()
    print("psum_17 OK")


if __name__ == "__main__":
    main()
