"""dac-48: Interpolation search.

Probe where the value should be by linear interpolation; O(log log n) on uniform data.
"""
import ast
import sys

DAC_48_VERSION = "dac-48.v1"

def interpolation_search(a, x):
    """Interpolation search on sorted ints; index of *x* or -1."""
    lo, hi = 0, len(a) - 1
    while lo <= hi and a[lo] <= x <= a[hi]:
        if a[hi] == a[lo]:
            return lo if a[lo] == x else -1
        pos = lo + (x - a[lo]) * (hi - lo) // (a[hi] - a[lo])
        if a[pos] == x:
            return pos
        if a[pos] < x:
            lo = pos + 1
        else:
            hi = pos - 1
    return -1

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    assert interpolation_search([], 1) == -1
    assert interpolation_search(list(range(100)), 42) == 42
    assert interpolation_search(list(range(100)), 0) == 0
    assert interpolation_search(list(range(100)), 99) == 99
    assert interpolation_search(list(range(0, 100, 2)), 43) == -1
    assert interpolation_search([5, 5, 5, 5], 5) == 0
    assert stdlib_only()
    print("dac-48 OK")


if __name__ == "__main__":
    main()
