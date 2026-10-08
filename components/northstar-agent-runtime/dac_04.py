"""dac-04: Quicksort (Hoare partition).

Divide and conquer around a pivot using Hoare's scheme (fewer swaps). Average O(n log n).
"""
import ast
import sys

DAC_04_VERSION = "dac-04.v1"

def _partition_hoare(a, lo, hi):
    pivot = a[(lo + hi) // 2]
    i, j = lo - 1, hi + 1
    while True:
        i += 1
        while a[i] < pivot:
            i += 1
        j -= 1
        while a[j] > pivot:
            j -= 1
        if i >= j:
            return j
        a[i], a[j] = a[j], a[i]


def _qs(a, lo, hi):
    if lo < hi:
        p = _partition_hoare(a, lo, hi)
        _qs(a, lo, p)
        _qs(a, p + 1, hi)


def quick_sort_hoare(a):
    """Quicksort with Hoare partition; returns a sorted copy."""
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
    assert quick_sort_hoare([]) == []
    assert quick_sort_hoare([1]) == [1]
    assert quick_sort_hoare([3, 1, 2]) == [1, 2, 3]
    assert quick_sort_hoare([8, 3, 7, 1, 9, 2]) == [1, 2, 3, 7, 8, 9]
    assert quick_sort_hoare([5, 5, 5, 1]) == [1, 5, 5, 5]
    assert stdlib_only()
    print("dac-04 OK")


if __name__ == "__main__":
    main()
