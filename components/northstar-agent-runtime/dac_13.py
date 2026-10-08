"""dac-13: Quickselect (k-th smallest).

Partition around a pivot, then recurse only into the side holding k. Average O(n).
"""
import ast
import sys

DAC_13_VERSION = "dac-13.v1"

def _partition(a, lo, hi):
    mid = (lo + hi) // 2
    pivot = a[mid]
    a[mid], a[hi] = a[hi], a[mid]
    i = lo
    for j in range(lo, hi):
        if a[j] < pivot:
            a[i], a[j] = a[j], a[i]
            i += 1
    a[i], a[hi] = a[hi], a[i]
    return i


def quickselect(a, k):
    """k-th smallest (0-based) via quickselect."""
    a = list(a)
    if not 0 <= k < len(a):
        raise ValueError("k out of range")
    lo, hi = 0, len(a) - 1
    while True:
        if lo == hi:
            return a[lo]
        p = _partition(a, lo, hi)
        if k == p:
            return a[k]
        if k < p:
            hi = p - 1
        else:
            lo = p + 1

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
    assert quickselect([3, 1, 2], 0) == 1
    assert quickselect([3, 1, 2], 2) == 3
    assert quickselect([7, 10, 4, 3, 20, 15], 3) == 10
    assert quickselect([5], 0) == 5
    try:
        quickselect([1, 2], 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-13 OK")


if __name__ == "__main__":
    main()
