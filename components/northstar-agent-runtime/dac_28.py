"""dac-28: K-th element of two sorted arrays.

Discard k/2 elements from one array per step. O(log k).
"""
import ast
import sys

DAC_28_VERSION = "dac-28.v1"

def _kth(A, B, k):
    # 1-based k
    if not A:
        return B[k - 1]
    if not B:
        return A[k - 1]
    if k == 1:
        return A[0] if A[0] < B[0] else B[0]
    i = min(len(A), k // 2)
    j = min(len(B), k // 2)
    if A[i - 1] <= B[j - 1]:
        return _kth(A[i:], B, k - i)
    return _kth(A, B[j:], k - j)


def kth_of_two_sorted(A, B, k):
    """k-th smallest (1-based) of two sorted arrays."""
    if k < 1 or k > len(A) + len(B):
        raise ValueError("k out of range")
    return _kth(list(A), list(B), k)

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
    assert kth_of_two_sorted([1, 3, 5], [2, 4, 6], 1) == 1
    assert kth_of_two_sorted([1, 3, 5], [2, 4, 6], 6) == 6
    assert kth_of_two_sorted([1, 3, 5], [2, 4, 6], 4) == 4
    assert kth_of_two_sorted([], [1, 2], 2) == 2
    assert kth_of_two_sorted([1, 2], [], 1) == 1
    try:
        kth_of_two_sorted([1], [2], 0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-28 OK")


if __name__ == "__main__":
    main()
