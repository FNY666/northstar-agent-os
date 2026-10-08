"""dac-27: Search sorted 2D matrix.

Quadrant divide and conquer on a row- and column-sorted matrix.
"""
import ast
import sys

DAC_27_VERSION = "dac-27.v1"

def _sm(m, x, r0, r1, c0, c1):
    if r0 > r1 or c0 > c1:
        return False
    rm = (r0 + r1) // 2
    cm = (c0 + c1) // 2
    v = m[rm][cm]
    if v == x:
        return True
    if v > x:
        return _sm(m, x, r0, r1, c0, cm - 1) or _sm(m, x, r0, rm - 1, cm, c1)
    return _sm(m, x, r0, r1, cm + 1, c1) or _sm(m, x, rm + 1, r1, c0, cm)


def search_matrix_dc(matrix, x):
    """Search a row/col-sorted matrix via quadrant divide and conquer."""
    if not matrix or not matrix[0]:
        return False
    return _sm(matrix, x, 0, len(matrix) - 1, 0, len(matrix[0]) - 1)

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
    M = [[1, 4, 7], [2, 5, 8], [3, 6, 9]]
    assert search_matrix_dc(M, 5) is True
    assert search_matrix_dc(M, 1) is True
    assert search_matrix_dc(M, 9) is True
    assert search_matrix_dc(M, 10) is False
    assert search_matrix_dc(M, 0) is False
    assert search_matrix_dc([], 1) is False
    assert stdlib_only()
    print("dac-27 OK")


if __name__ == "__main__":
    main()
