"""lis-17: Longest pair chain.

Greedy by end time: chain pairs with b < c (LeetCode 646).

Time complexity: O(n log n) time
Space complexity: O(n)"""

import ast
import sys
LIS_17_VERSION = "lis-17.v1"


def _check_pairs(pairs):
    """Validate pairs is a list/tuple of 2-number pairs; return list of [w, h]."""
    if not isinstance(pairs, (list, tuple)):
        raise ValueError("pairs must be a list or tuple")
    out = []
    for p in pairs:
        if not isinstance(p, (list, tuple)) or len(p) != 2:
            raise ValueError("each pair must have length 2")
        w, h = p
        if not isinstance(w, (int, float)) or not isinstance(h, (int, float)):
            raise ValueError("pair elements must be numbers")
        out.append([w, h])
    return out
def longest_pair_chain(pairs):
    """Maximum size of a chain with pair[i][1] < pair[j][0]."""
    pts = _check_pairs(pairs)
    pts.sort(key=lambda p: p[1])
    count = 0
    prev_end = None
    for s, e in pts:
        if prev_end is None or s > prev_end:
            count += 1
            prev_end = e
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
    assert longest_pair_chain([[1, 2], [2, 3], [3, 4]]) == 2
    assert longest_pair_chain([[1, 2], [7, 8], [4, 5]]) == 3
    assert longest_pair_chain([]) == 0
    assert stdlib_only()
    print("lis-17 OK")


if __name__ == "__main__":
    main()
