"""dac-11: Maximum subarray (divide and conquer).

Split in half; the answer is in the left half, right half, or crossing the middle.
"""
import ast
import sys

DAC_11_VERSION = "dac-11.v1"

def _max_cross(a, lo, mid, hi):
    left = float("-inf")
    s = 0
    for i in range(mid, lo - 1, -1):
        s += a[i]
        if s > left:
            left = s
    right = float("-inf")
    s = 0
    for i in range(mid + 1, hi + 1):
        s += a[i]
        if s > right:
            right = s
    return left + right


def _ms(a, lo, hi):
    if lo == hi:
        return a[lo]
    mid = (lo + hi) // 2
    return max(_ms(a, lo, mid), _ms(a, mid + 1, hi), _max_cross(a, lo, mid, hi))


def max_subarray(a):
    """Maximum subarray sum via divide and conquer."""
    if not a:
        raise ValueError("empty")
    return _ms(list(a), 0, len(a) - 1)

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
    assert max_subarray([-2, 1, -3, 4, -1, 2, 1, -5, 4]) == 6
    assert max_subarray([1, 2, 3]) == 6
    assert max_subarray([-1, -2, -3]) == -1
    assert max_subarray([5]) == 5
    try:
        max_subarray([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-11 OK")


if __name__ == "__main__":
    main()
