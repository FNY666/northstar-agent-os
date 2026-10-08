"""intv_15: My Calendar III: maximum concurrent bookings (calendar_three).

Sweep line over all bookings; track the peak overlap.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_15 = "intv-15.v1"


def max_k_booking(seq):
    """Return the maximum number of simultaneous bookings after each book."""
    events = []
    res = []
    for s, e in seq:
        events.append((s, 1)); events.append((e, -1))
        events.sort(key=lambda x: (x[0], x[1]))
        cur = best = 0
        for _, d in events:
            cur += d
            if cur > best:
                best = cur
        res.append(best)
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
    assert max_k_booking([(10, 20), (50, 60), (10, 40), (5, 15), (5, 10), (25, 55)]) == [1, 1, 2, 3, 3, 3]
    assert max_k_booking([(1, 5)]) == [1]
    assert max_k_booking([]) == []
    assert max_k_booking([(1, 2), (2, 3), (3, 4)]) == [1, 1, 1]
    assert max_k_booking([(1, 10), (2, 9), (3, 8)]) == [1, 2, 3]
    assert stdlib_only()
    print("intv_15 OK")


if __name__ == "__main__":
    main()
