"""greedy_14: Assign cookies.

Match the least greedy child with the smallest cookie that satisfies them.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_14_VERSION = "greedy-14.v1"


def assign_cookies(greed, sizes):
    """Return the maximum number of content children."""
    greed = sorted(greed)
    sizes = sorted(sizes)
    i = j = 0
    while i < len(greed) and j < len(sizes):
        if sizes[j] >= greed[i]:
            i += 1
        j += 1
    return i

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
    assert assign_cookies([1, 2, 3], [1, 1]) == 1
    assert assign_cookies([1, 2], [1, 2, 3]) == 2
    assert assign_cookies([], [1]) == 0
    assert assign_cookies([1, 2, 3], []) == 0
    assert stdlib_only()
    print("greedy_14 OK")


if __name__ == "__main__":
    main()
