"""dac-35: Wiggle sort.

Find the median by divide-and-conquer selection, then interleave the halves: a0<=a1>=a2<=... .
"""
import ast
import sys

DAC_35_VERSION = "dac-35.v1"

def _partition(a, lo, hi):
    pivot = a[hi]
    i = lo
    for j in range(lo, hi):
        if a[j] <= pivot:
            a[i], a[j] = a[j], a[i]
            i += 1
    a[i], a[hi] = a[hi], a[i]
    return i


def _quickselect(a, k):
    lo, hi = 0, len(a) - 1
    while lo < hi:
        p = _partition(a, lo, hi)
        if p == k:
            break
        if p < k:
            lo = p + 1
        else:
            hi = p - 1
    return a[k]


def _is_wiggle(a):
    for i in range(len(a) - 1):
        if i % 2 == 0:
            if a[i] > a[i + 1]:
                return False
        else:
            if a[i] < a[i + 1]:
                return False
    return True


def wiggle_sort_dc(a):
    """Rearrange into a0 <= a1 >= a2 <= a3 ... via median divide and conquer."""
    a = list(a)
    n = len(a)
    if n <= 1:
        return a
    med = _quickselect(list(a), n // 2)
    small = sorted(x for x in a if x < med)
    equal = [x for x in a if x == med]
    large = sorted(x for x in a if x > med)
    left = (small + equal)[: (n + 1) // 2][::-1]
    right = (small + equal)[(n + 1) // 2:][::-1] + large[::-1]
    res = []
    for i in range(len(right)):
        res.append(left[i])
        res.append(right[i])
    if len(left) > len(right):
        res.append(left[-1])
    return res

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
    assert _is_wiggle(wiggle_sort_dc([3, 5, 2, 1, 6, 4]))
    assert _is_wiggle(wiggle_sort_dc([1, 2, 3, 4, 5]))
    assert _is_wiggle(wiggle_sort_dc([1]))
    assert sorted(wiggle_sort_dc([3, 5, 2, 1, 6, 4])) == [1, 2, 3, 4, 5, 6]
    assert stdlib_only()
    print("dac-35 OK")


if __name__ == "__main__":
    main()
