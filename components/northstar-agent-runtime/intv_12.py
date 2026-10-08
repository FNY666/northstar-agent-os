"""intv_12: Corporate flight bookings via difference array (flight_bookings).

Record +seats at first, -seats after last, then prefix-sum.

Time complexity: O(n + m) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_12 = "intv-12.v1"


def flight_bookings(bookings, n):
    """Return seats booked on each of ``n`` flights."""
    diff = [0] * (n + 1)
    for first, last, seats in bookings:
        diff[first - 1] += seats
        diff[last] -= seats
    res = []
    cur = 0
    for i in range(n):
        cur += diff[i]
        res.append(cur)
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
    assert flight_bookings([(1, 2, 10), (2, 3, 20), (2, 5, 25)], 5) == [10, 55, 45, 25, 25]
    assert flight_bookings([(1, 2, 10), (2, 2, 15)], 2) == [10, 25]
    assert flight_bookings([], 3) == [0, 0, 0]
    assert flight_bookings([(1, 1, 5)], 1) == [5]
    assert flight_bookings([(1, 3, 2), (1, 3, 3)], 3) == [5, 5, 5]
    assert stdlib_only()
    print("intv_12 OK")


if __name__ == "__main__":
    main()
