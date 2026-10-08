"""dac-43: Count negatives in sorted matrix.

Split the row range in half; each single row is binary-searched. Matrix is non-increasing.
"""
import ast
import sys

DAC_43_VERSION = "dac-43.v1"

def _count_rows(m, r0, r1):
    if r0 > r1:
        return 0
    if r0 == r1:
        row = m[r0]
        n = len(row)
        lo, hi, ans = 0, n - 1, n
        while lo <= hi:
            mid = (lo + hi) // 2
            if row[mid] < 0:
                ans = mid
                hi = mid - 1
            else:
                lo = mid + 1
        return n - ans
    mid = (r0 + r1) // 2
    return _count_rows(m, r0, mid) + _count_rows(m, mid + 1, r1)


def count_negatives_dc(matrix):
    """Count negatives in a row/col non-increasing matrix via D&C."""
    if not matrix or not matrix[0]:
        return 0
    return _count_rows(matrix, 0, len(matrix) - 1)

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
    assert count_negatives_dc([]) == 0
    assert count_negatives_dc([[4, 3, 2, -1], [3, 2, 1, -1], [1, 1, -1, -2]]) == 4
    assert count_negatives_dc([[1, 2], [3, 4]]) == 0
    assert count_negatives_dc([[-1, -2], [-3, -4]]) == 4
    assert count_negatives_dc([[5]]) == 0
    assert stdlib_only()
    print("dac-43 OK")


if __name__ == "__main__":
    main()
