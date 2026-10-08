"""dac-37: Maximum circular subarray.

Divide-and-conquer max/min subarrays: answer is max(linear, total - min).
"""
import ast
import sys

DAC_37_VERSION = "dac-37.v1"

def _extreme(a, lo, hi, want_max):
    if lo == hi:
        return a[lo]
    mid = (lo + hi) // 2
    left = _extreme(a, lo, mid, want_max)
    right = _extreme(a, mid + 1, hi, want_max)
    if want_max:
        best_l, s = float("-inf"), 0
        for i in range(mid, lo - 1, -1):
            s += a[i]
            best_l = max(best_l, s)
        best_r, s = float("-inf"), 0
        for i in range(mid + 1, hi + 1):
            s += a[i]
            best_r = max(best_r, s)
        return max(left, right, best_l + best_r)
    best_l, s = float("inf"), 0
    for i in range(mid, lo - 1, -1):
        s += a[i]
        best_l = min(best_l, s)
    best_r, s = float("inf"), 0
    for i in range(mid + 1, hi + 1):
        s += a[i]
        best_r = min(best_r, s)
    return min(left, right, best_l + best_r)


def max_subarray_circular(a):
    """Maximum subarray sum on a circular array via divide and conquer."""
    a = list(a)
    if not a:
        raise ValueError("empty")
    best = _extreme(a, 0, len(a) - 1, True)
    if best < 0:
        return best
    worst = _extreme(a, 0, len(a) - 1, False)
    return max(best, sum(a) - worst)

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
    assert max_subarray_circular([1, -2, 3, -2]) == 3
    assert max_subarray_circular([5, -3, 5]) == 10
    assert max_subarray_circular([-3, -2, -3]) == -2
    assert max_subarray_circular([3, 1, 3, 2, 6]) == 15
    try:
        max_subarray_circular([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-37 OK")


if __name__ == "__main__":
    main()
