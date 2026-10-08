"""intv_21: Common free time across employees (employee_free).

Flatten all busy intervals, merge, then take the gaps.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_21 = "intv-21.v1"


def employee_free_time(schedule):
    """Return finite intervals where every employee is free."""
    busy = [iv for emp in schedule for iv in emp]
    if not busy:
        return []
    busy.sort(key=lambda x: x[0])
    merged = [list(busy[0])]
    for s, e in busy[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [(merged[i][1], merged[i + 1][0]) for i in range(len(merged) - 1)]

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
    assert employee_free_time([[(1, 2), (5, 6)], [(1, 3)], [(4, 10)]]) == [(3, 4)]
    assert employee_free_time([[(1, 3), (6, 7)], [(2, 4)], [(2, 5), (9, 12)]]) == [(5, 6), (7, 9)]
    assert employee_free_time([[(1, 2)]]) == []
    assert employee_free_time([]) == []
    assert employee_free_time([[(1, 5)], [(2, 3)]]) == []
    assert stdlib_only()
    print("intv_21 OK")


if __name__ == "__main__":
    main()
