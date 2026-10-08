"""psum_38: Cumulative Distinct Count

Running distinct tally gives distinct-count for every prefix in O(n).

Time complexity: O(n) time
Space complexity: O(n)"""

import ast
import sys
PSUM_38_VERSION = "psum-38.v1"


def prefix_distinct(a):
    last = {}
    out = []
    d = 0
    for x in a:
        if x not in last:
            d += 1
        last[x] = True
        out.append(d)
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
    assert prefix_distinct([1, 2, 1, 3, 2]) == [1, 2, 2, 3, 3]
    assert prefix_distinct([]) == []
    assert prefix_distinct([7, 7, 7]) == [1, 1, 1]
    assert prefix_distinct([1, 2, 3]) == [1, 2, 3]
    assert stdlib_only()
    print("psum_38 OK")


if __name__ == "__main__":
    main()
