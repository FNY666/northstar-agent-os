"""dac-02: Merge sort (bottom-up).

Iterative divide-and-conquer sort: merge runs of doubling width. O(n log n), no recursion.
"""
import ast
import sys

DAC_02_VERSION = "dac-02.v1"

def merge_runs(a, lo, mid, hi, buf):
    i, j, k = lo, mid, lo
    while i < mid and j < hi:
        if a[i] <= a[j]:
            buf[k] = a[i]
            i += 1
        else:
            buf[k] = a[j]
            j += 1
        k += 1
    while i < mid:
        buf[k] = a[i]
        i += 1
        k += 1
    while j < hi:
        buf[k] = a[j]
        j += 1
        k += 1
    a[lo:hi] = buf[lo:hi]


def merge_sort_bottom_up(a):
    """Iterative bottom-up merge sort; returns a sorted copy."""
    a = list(a)
    n = len(a)
    buf = [0] * n
    width = 1
    while width < n:
        for lo in range(0, n, 2 * width):
            mid = min(lo + width, n)
            hi = min(lo + 2 * width, n)
            if mid < hi:
                merge_runs(a, lo, mid, hi, buf)
        width *= 2
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
    assert merge_sort_bottom_up([]) == []
    assert merge_sort_bottom_up([1]) == [1]
    assert merge_sort_bottom_up([3, 1, 2]) == [1, 2, 3]
    assert merge_sort_bottom_up([9, 7, 5, 3, 1, 2, 4, 6, 8]) == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert merge_sort_bottom_up([4, 4, 4]) == [4, 4, 4]
    assert stdlib_only()
    print("dac-02 OK")


if __name__ == "__main__":
    main()
