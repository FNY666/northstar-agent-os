"""dp-42: Maximum length of pair chain.

Longest chain of pairs where each pair starts after the previous ends. Greedy by earliest finishing pair is optimal.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
from typing import List

DP_42_VERSION = "dp-42.v1"


def pair_chain(pairs: List[List[int]]) -> int:
    """Return the maximum length chain of non-overlapping pairs."""
    ordered = sorted(pairs, key=lambda p: p[1])
    cur = float("-inf")
    count = 0
    for a, b in ordered:
        if a > cur:
            cur = b
            count += 1
    return count


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
    assert pair_chain([[1, 2], [2, 3], [3, 4]]) == 2
    assert pair_chain([[1, 2], [7, 8], [4, 5]]) == 3
    assert pair_chain([]) == 0
    assert pair_chain([[-10, -8], [8, 9]]) == 2
    assert pair_chain([[3, 4], [2, 3], [1, 2]]) == 2
    assert stdlib_only()
    print("dp-42 OK")


if __name__ == "__main__":
    main()
