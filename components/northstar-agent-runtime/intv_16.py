"""intv_16: Count days covered by task intervals (covered_days).

Merge intervals, then sum their lengths.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_16 = "intv-16.v1"


def covered_days(tasks):
    """Return total integer days covered by [start, end] tasks."""
    if not tasks:
        return 0
    ivs = sorted(tasks, key=lambda x: x[0])
    total = 0
    cs, ce = ivs[0]
    for s, e in ivs[1:]:
        if s <= ce + 1:
            if e > ce:
                ce = e
        else:
            total += ce - cs + 1
            cs, ce = s, e
    total += ce - cs + 1
    return total

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
    assert covered_days([(1, 6), (8, 10), (9, 12)]) == 11
    assert covered_days([(1, 4), (4, 4)]) == 4
    assert covered_days([]) == 0
    assert covered_days([(5, 5)]) == 1
    assert covered_days([(1, 2), (4, 5)]) == 4
    assert stdlib_only()
    print("intv_16 OK")


if __name__ == "__main__":
    main()
