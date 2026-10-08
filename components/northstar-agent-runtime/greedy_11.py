"""greedy_11: Non-overlapping intervals (erase overlap).

Keep the interval ending earliest; drop any interval starting before it ends.

Time complexity: O(n log n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
GREEDY_11_VERSION = "greedy-11.v1"


def erase_overlap_intervals(intervals):
    """Return the minimum number of intervals to remove so the rest are disjoint."""
    if not intervals:
        return 0
    ordered = sorted(intervals, key=lambda x: x[1])
    removed = 0
    end = ordered[0][1]
    for s, e in ordered[1:]:
        if s < end:
            removed += 1
        else:
            end = e
    return removed

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
    assert erase_overlap_intervals([[1, 2], [2, 3], [3, 4], [1, 3]]) == 1
    assert erase_overlap_intervals([[1, 2], [1, 2], [1, 2]]) == 2
    assert erase_overlap_intervals([]) == 0
    assert erase_overlap_intervals([[1, 2], [2, 3]]) == 0
    assert stdlib_only()
    print("greedy_11 OK")


if __name__ == "__main__":
    main()
