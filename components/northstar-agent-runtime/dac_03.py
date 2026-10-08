"""dac-03: Quicksort (Lomuto partition).

Divide and conquer around a pivot using Lomuto's scheme. Average O(n log n).
"""
import ast
import sys

DAC_03_VERSION = "dac-03.v1"

def _partition(a, lo, hi):
    pivot = a[hi]
    i = lo
    for j in range(lo, hi):
        if a[j] <= pivot:
            a[i], a[j] = a[j], a[i]
            i += 1
    a[i], a[hi] = a[hi], a[i]
    return i


def _qs(a, lo, hi):
    if lo < hi:
        p = _partition(a, lo, hi)
        _qs(a, lo, p - 1)
        _qs(a, p + 1, hi)


def quick_sort(a):
    """Quicksort with Lomuto partition; returns a sorted copy."""
    a = list(a)
    _qs(a, 0, len(a) - 1)
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
    assert quick_sort([]) == []
    assert quick_sort([1]) == [1]
    assert quick_sort([3, 1, 2]) == [1, 2, 3]
    assert quick_sort([5, 1, 4, 2, 3]) == [1, 2, 3, 4, 5]
    assert quick_sort([2, 1, 2, 1]) == [1, 1, 2, 2]
    assert stdlib_only()
    print("dac-03 OK")


if __name__ == "__main__":
    main()
