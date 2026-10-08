"""intv_34: For each interval find the next non-overlapping one (right_interval).

Sort starts; binary search the smallest start >= current end.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import bisect
INTV_34 = "intv-34.v1"


def right_interval(intervals):
    """For each interval, index of the interval with smallest start >= its end."""
    starts = sorted((s, i) for i, (s, e) in enumerate(intervals))
    s_vals = [s for s, _ in starts]
    res = []
    for s, e in intervals:
        j = bisect.bisect_left(s_vals, e)
        res.append(starts[j][1] if j < len(starts) else -1)
    return res

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
    assert right_interval([(1, 2)]) == [-1]
    assert right_interval([(3, 4), (2, 3), (1, 2)]) == [-1, 0, 1]
    assert right_interval([(1, 4), (2, 3), (3, 4)]) == [-1, 2, -1]
    assert right_interval([]) == []
    assert right_interval([(1, 2), (2, 3)]) == [1, -1]
    assert stdlib_only()
    print("intv_34 OK")


if __name__ == "__main__":
    main()
