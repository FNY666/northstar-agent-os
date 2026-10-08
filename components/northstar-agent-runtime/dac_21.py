"""dac-21: First and last occurrence.

Two biased binary searches: keep going left (or right) after a hit. O(log n).
"""
import ast
import sys

DAC_21_VERSION = "dac-21.v1"

def _edge(a, x, lo, hi, want_first):
    ans = -1
    while lo <= hi:
        mid = (lo + hi) // 2
        if a[mid] == x:
            ans = mid
            if want_first:
                hi = mid - 1
            else:
                lo = mid + 1
        elif a[mid] < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return ans


def first_last(a, x):
    """(first_index, last_index) of *x* in sorted *a*; -1 if absent."""
    a = list(a)
    return (_edge(a, x, 0, len(a) - 1, True), _edge(a, x, 0, len(a) - 1, False))

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
    assert first_last([1, 2, 2, 2, 3], 2) == (1, 3)
    assert first_last([1, 2, 3], 2) == (1, 1)
    assert first_last([1, 2, 3], 9) == (-1, -1)
    assert first_last([], 1) == (-1, -1)
    assert first_last([5, 5, 5], 5) == (0, 2)
    assert stdlib_only()
    print("dac-21 OK")


if __name__ == "__main__":
    main()
