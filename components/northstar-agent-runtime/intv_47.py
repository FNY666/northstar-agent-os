"""intv_47: Two best non-overlapping events (two_best_events).

Sort by start; suffix-max of values, binary search compatible partner.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import bisect
INTV_47 = "intv-47.v1"


def two_best_events(events):
    """Max sum of values of two non-overlapping events."""
    events = sorted(events, key=lambda x: x[0])
    n = len(events)
    starts = [e[0] for e in events]
    suffix = [0] * (n + 1)
    for i in range(n - 1, -1, -1):
        suffix[i] = max(suffix[i + 1], events[i][2])
    best = 0
    for i, (s, e, v) in enumerate(events):
        j = bisect.bisect_right(starts, e, i + 1)
        if j < n:
            best = max(best, v + suffix[j])
    return best

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
    assert two_best_events([[1, 3, 2], [4, 5, 2], [2, 4, 3]]) == 4
    assert two_best_events([[1, 3, 2], [4, 5, 2], [1, 5, 5]]) == 5
    assert two_best_events([[1, 5, 3], [1, 5, 1], [6, 6, 5]]) == 8
    assert two_best_events([[1, 2, 1]]) == 0
    assert two_best_events([[10, 20, 10], [1, 5, 5], [6, 9, 6]]) == 16
    assert stdlib_only()
    print("intv_47 OK")


if __name__ == "__main__":
    main()
