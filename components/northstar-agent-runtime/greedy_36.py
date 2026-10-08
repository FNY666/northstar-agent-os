"""greedy_36: Hand of straights.

Repeatedly form a straight starting from the smallest remaining card.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_36_VERSION = "greedy-36.v1"


def hand_of_straights(hand, group_size):
    """Return True if the hand splits into straights of group_size."""
    from collections import Counter
    if len(hand) % group_size:
        return False
    counts = Counter(hand)
    for x in sorted(counts):
        need = counts[x]
        if need:
            for y in range(x, x + group_size):
                if counts[y] < need:
                    return False
                counts[y] -= need
    return True

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
    assert hand_of_straights([1, 2, 3, 6, 2, 3, 4, 7, 8], 3) is True
    assert hand_of_straights([1, 2, 3, 4, 5], 4) is False
    assert hand_of_straights([], 3) is True
    assert hand_of_straights([1, 1, 2, 2, 3, 3], 3) is True
    assert stdlib_only()
    print("greedy_36 OK")


if __name__ == "__main__":
    main()
