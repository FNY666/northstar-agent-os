"""greedy_01: Activity selection.

Pick the maximum number of non-overlapping activities by always taking the activity that ends earliest.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_01_VERSION = "greedy-01.v1"


def max_activities(activities):
    """Return the max number of non-overlapping activities.

    activities: iterable of (start, end) pairs.
    """
    acts = sorted(activities, key=lambda a: a[1])
    count = 0
    last_end = float("-inf")
    for s, e in acts:
        if s >= last_end:
            count += 1
            last_end = e
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
    assert max_activities([(1, 2), (3, 4), (0, 6), (5, 7), (8, 9), (5, 9)]) == 4
    assert max_activities([]) == 0
    assert max_activities([(1, 1)]) == 1
    assert max_activities([(1, 4), (2, 3), (3, 5)]) == 2
    assert stdlib_only()
    print("greedy_01 OK")


if __name__ == "__main__":
    main()
