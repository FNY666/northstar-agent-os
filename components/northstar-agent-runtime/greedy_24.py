"""greedy_24: Candy distribution.

Two passes: left-to-right then right-to-left, taking the max requirement at each child.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_24_VERSION = "greedy-24.v1"


def candy(ratings):
    """Return the minimum candies so higher-rated neighbors get more."""
    n = len(ratings)
    if n == 0:
        return 0
    c = [1] * n
    for i in range(1, n):
        if ratings[i] > ratings[i - 1]:
            c[i] = c[i - 1] + 1
    for i in range(n - 2, -1, -1):
        if ratings[i] > ratings[i + 1]:
            c[i] = max(c[i], c[i + 1] + 1)
    return sum(c)

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
    assert candy([1, 0, 2]) == 5
    assert candy([1, 2, 2]) == 4
    assert candy([]) == 0
    assert candy([1, 3, 4, 5, 2]) == 11
    assert stdlib_only()
    print("greedy_24 OK")


if __name__ == "__main__":
    main()
