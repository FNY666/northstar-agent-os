"""dac-12: Inversion count (merge-sort based).

Count inversions while merging: each right element taken before left ones adds len(left)-i.
"""
import ast
import sys

DAC_12_VERSION = "dac-12.v1"

def _sort_count(a):
    n = len(a)
    if n <= 1:
        return list(a), 0
    mid = n // 2
    left, cl = _sort_count(a[:mid])
    right, cr = _sort_count(a[mid:])
    merged = []
    i = j = 0
    c = cl + cr
    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
            c += len(left) - i
    merged.extend(left[i:])
    merged.extend(right[j:])
    return merged, c


def inversion_count(a):
    """Number of inversions via merge-sort divide and conquer."""
    return _sort_count(list(a))[1]

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
    assert inversion_count([]) == 0
    assert inversion_count([1, 2, 3]) == 0
    assert inversion_count([3, 2, 1]) == 3
    assert inversion_count([2, 4, 1, 3, 5]) == 3
    assert inversion_count([5, 4, 3, 2, 1]) == 10
    assert stdlib_only()
    print("dac-12 OK")


if __name__ == "__main__":
    main()
