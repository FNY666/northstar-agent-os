"""dac-44: 2D peak finding.

Binary search on columns: the column max's larger neighbor tells which half holds a peak.
"""
import ast
import sys

DAC_44_VERSION = "dac-44.v1"

def _peak2d(m, c0, c1):
    cm = (c0 + c1) // 2
    r = max(range(len(m)), key=lambda i: m[i][cm])
    left_ok = cm == c0 or m[r][cm] >= m[r][cm - 1]
    right_ok = cm == c1 or m[r][cm] >= m[r][cm + 1]
    if left_ok and right_ok:
        return (r, cm)
    if cm > c0 and m[r][cm - 1] > m[r][cm]:
        return _peak2d(m, c0, cm - 1)
    return _peak2d(m, cm + 1, c1)


def _is_peak2d(m, r, c):
    v = m[r][c]
    for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        nr, nc = r + dr, c + dc
        if 0 <= nr < len(m) and 0 <= nc < len(m[0]) and m[nr][nc] > v:
            return False
    return True


def peak_2d(matrix):
    """(row, col) of a 2D peak via column divide and conquer."""
    if not matrix or not matrix[0]:
        raise ValueError("empty")
    return _peak2d(matrix, 0, len(matrix[0]) - 1)

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
    M = [[1, 4, 3], [6, 5, 2], [7, 8, 9]]
    r, c = peak_2d(M)
    assert _is_peak2d(M, r, c)
    M2 = [[10, 8], [9, 7]]
    r, c = peak_2d(M2)
    assert _is_peak2d(M2, r, c)
    assert peak_2d([[42]]) == (0, 0)
    try:
        peak_2d([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-44 OK")


if __name__ == "__main__":
    main()
