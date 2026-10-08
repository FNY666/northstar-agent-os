"""Matrix determinant via Gaussian elimination.

det: general n x n determinant (partial pivoting, float).
det_2x2: exact 2x2 formula.
"""

from __future__ import annotations


def _check_square(M) -> int:
    if not M:
        raise ValueError("empty matrix")
    n = len(M)
    for row in M:
        if len(row) != n:
            raise ValueError("matrix must be square")
    return n


def det(M) -> float:
    """Determinant of a square matrix."""
    n = _check_square(M)
    A = [list(map(float, row)) for row in M]
    sign = 1.0
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(A[r][col]))
        if abs(A[pivot][col]) < 1e-12:
            return 0.0
        if pivot != col:
            A[col], A[pivot] = A[pivot], A[col]
            sign = -sign
        for r in range(col + 1, n):
            factor = A[r][col] / A[col][col]
            for c in range(col, n):
                A[r][c] -= factor * A[col][c]
    d = sign
    for i in range(n):
        d *= A[i][i]
    return d


def det_2x2(a, b, c, d):
    """Exact determinant of [[a, b], [c, d]]."""
    return a * d - b * c


def main() -> None:
    assert det_2x2(1, 2, 3, 4) == -2
    assert abs(det([[1, 2], [3, 4]]) - (-2.0)) < 1e-9
    assert abs(det([[1, 0, 0], [0, 1, 0], [0, 0, 1]]) - 1.0) < 1e-9
    assert det([[1, 2], [2, 4]]) == 0.0
    assert abs(det([[6, 1, 1], [4, -2, 5], [2, 8, 7]]) - (-306.0)) < 1e-6
    print("math_08 OK")


if __name__ == "__main__":
    main()
