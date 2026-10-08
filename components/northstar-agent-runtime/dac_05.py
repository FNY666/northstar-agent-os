"""dac-05: Quicksort (3-way, Dutch flag).

Three-way divide and conquer; groups equal keys so duplicates cost O(n).
"""
import ast
import sys

DAC_05_VERSION = "dac-05.v1"

def _qs3(a, lo, hi):
    if lo >= hi:
        return
    pivot = a[lo]
    lt, i, gt = lo, lo + 1, hi
    while i <= gt:
        if a[i] < pivot:
            a[lt], a[i] = a[i], a[lt]
            lt += 1
            i += 1
        elif a[i] > pivot:
            a[i], a[gt] = a[gt], a[i]
            gt -= 1
        else:
            i += 1
    _qs3(a, lo, lt - 1)
    _qs3(a, gt + 1, hi)


def quick_sort_3way(a):
    """3-way quicksort; fast when many duplicates exist."""
    a = list(a)
    _qs3(a, 0, len(a) - 1)
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
    assert quick_sort_3way([]) == []
    assert quick_sort_3way([2, 2, 2, 2]) == [2, 2, 2, 2]
    assert quick_sort_3way([3, 1, 2, 1, 3, 2]) == [1, 1, 2, 2, 3, 3]
    assert quick_sort_3way([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert stdlib_only()
    print("dac-05 OK")


if __name__ == "__main__":
    main()
