"""dac-20: Peak element.

If a[mid] < a[mid+1] the peak is right, else left. O(log n) divide and conquer.
"""
import ast
import sys

DAC_20_VERSION = "dac-20.v1"

def _fp(a, lo, hi):
    if lo == hi:
        return lo
    mid = (lo + hi) // 2
    if a[mid] < a[mid + 1]:
        return _fp(a, mid + 1, hi)
    return _fp(a, lo, mid)


def _is_peak(a, i):
    left_ok = i == 0 or a[i] >= a[i - 1]
    right_ok = i == len(a) - 1 or a[i] >= a[i + 1]
    return left_ok and right_ok


def find_peak(a):
    """Index of a peak element via divide and conquer."""
    if not a:
        raise ValueError("empty")
    return _fp(list(a), 0, len(a) - 1)

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
    assert _is_peak([1, 2, 3, 1], find_peak([1, 2, 3, 1]))
    assert _is_peak([1, 2, 1, 3, 5, 6, 4], find_peak([1, 2, 1, 3, 5, 6, 4]))
    assert find_peak([5]) == 0
    try:
        find_peak([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-20 OK")


if __name__ == "__main__":
    main()
