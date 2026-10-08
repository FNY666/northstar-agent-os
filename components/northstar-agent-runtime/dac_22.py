"""dac-22: Integer square root.

Binary search on answer space: floor(sqrt(n)) in O(log n).
"""
import ast
import sys

DAC_22_VERSION = "dac-22.v1"

def _isqrt(n, lo, hi):
    if lo > hi:
        return hi
    mid = (lo + hi) // 2
    sq = mid * mid
    if sq == n:
        return mid
    if sq < n:
        return _isqrt(n, mid + 1, hi)
    return _isqrt(n, lo, mid - 1)


def integer_sqrt(n):
    """Floor of sqrt(n) by binary search; n must be non-negative."""
    if n < 0:
        raise ValueError("negative")
    return _isqrt(n, 0, n)

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
    assert integer_sqrt(0) == 0
    assert integer_sqrt(1) == 1
    assert integer_sqrt(15) == 3
    assert integer_sqrt(16) == 4
    assert integer_sqrt(10 ** 12) == 10 ** 6
    try:
        integer_sqrt(-4)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-22 OK")


if __name__ == "__main__":
    main()
