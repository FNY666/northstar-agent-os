"""intv_33: Count intersecting interval pairs (count_intersecting_pairs).

Sweep starts and ends; each start meets all currently open intervals.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_33 = "intv-33.v1"


def count_intersecting_pairs(intervals):
    """Count unordered pairs of intervals that intersect (touching counts)."""
    events = []
    for s, e in intervals:
        events.append((s, 0)); events.append((e, 1))
    events.sort(key=lambda x: (x[0], x[1]))
    open_n = 0
    pairs = 0
    for _, kind in events:
        if kind == 0:
            pairs += open_n
            open_n += 1
        else:
            open_n -= 1
    return pairs

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
    assert count_intersecting_pairs([(1, 3), (2, 4), (5, 6)]) == 1
    assert count_intersecting_pairs([(1, 2), (3, 4)]) == 0
    assert count_intersecting_pairs([(1, 5), (2, 3), (4, 6)]) == 2
    assert count_intersecting_pairs([]) == 0
    assert count_intersecting_pairs([(1, 2), (2, 3)]) == 1
    assert stdlib_only()
    print("intv_33 OK")


if __name__ == "__main__":
    main()
