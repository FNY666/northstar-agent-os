"""dac-49: Dual-pivot quicksort.

Partition into three regions with two pivots (Yaroslavskiy-style), recurse on each.
"""
import ast
import sys

DAC_49_VERSION = "dac-49.v1"

def _dp_sort(a, lo, hi):
    if lo >= hi:
        return
    if a[lo] > a[hi]:
        a[lo], a[hi] = a[hi], a[lo]
    p, q = a[lo], a[hi]
    l, g = lo + 1, hi - 1
    k = l
    while k <= g:
        if a[k] < p:
            a[k], a[l] = a[l], a[k]
            l += 1
        elif a[k] > q:
            while a[g] > q and k < g:
                g -= 1
            a[k], a[g] = a[g], a[k]
            g -= 1
            if a[k] < p:
                a[k], a[l] = a[l], a[k]
                l += 1
        k += 1
    l -= 1
    g += 1
    a[lo], a[l] = a[l], a[lo]
    a[hi], a[g] = a[g], a[hi]
    _dp_sort(a, lo, l - 1)
    _dp_sort(a, l + 1, g - 1)
    _dp_sort(a, g + 1, hi)


def dual_pivot_quicksort(a):
    """Dual-pivot quicksort; returns a sorted copy."""
    a = list(a)
    _dp_sort(a, 0, len(a) - 1)
    return a

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
    assert dual_pivot_quicksort([]) == []
    assert dual_pivot_quicksort([1]) == [1]
    assert dual_pivot_quicksort([3, 1, 2]) == [1, 2, 3]
    assert dual_pivot_quicksort([9, 4, 7, 1, 8, 2, 6, 3, 5]) == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert dual_pivot_quicksort([2, 2, 1, 1, 3]) == [1, 1, 2, 2, 3]
    assert stdlib_only()
    print("dac-49 OK")


if __name__ == "__main__":
    main()
