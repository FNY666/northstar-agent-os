"""Solve Ax = b via Gaussian elimination with partial pivoting."""

from __future__ import annotations


def gaussian_solve(A, b):
    """Solve the n x n system. Raises ValueError if singular."""
    n = len(A)
    if n == 0 or any(len(row) != n for row in A) or len(b) != n:
        raise ValueError("bad dimensions")
    M = [list(map(float, row)) + [float(b[i])] for i, row in enumerate(A)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(M[r][col]))
        if abs(M[piv][col]) < 1e-12:
            raise ValueError("singular matrix")
        M[col], M[piv] = M[piv], M[col]
        for r in range(col + 1, n):
            factor = M[r][col] / M[col][col]
            for c in range(col, n + 1):
                M[r][c] -= factor * M[col][c]
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        s = M[i][n] - sum(M[i][j] * x[j] for j in range(i + 1, n))
        x[i] = s / M[i][i]
    return x


def main() -> None:
    x = gaussian_solve([[2, 1], [1, 3]], [5, 6])
    assert abs(x[0] - 1.8) < 1e-9 and abs(x[1] - 1.4) < 1e-9
    x = gaussian_solve([[1, 0, 0], [0, 1, 0], [0, 0, 1]], [1, 2, 3])
    assert x == [1.0, 2.0, 3.0]
    # residual check on a 3x3
    A = [[3, 2, -1], [2, -2, 4], [-1, 0.5, -1]]
    b = [1, -2, 0]
    x = gaussian_solve(A, b)
    for i in range(3):
        assert abs(sum(A[i][j] * x[j] for j in range(3)) - b[i]) < 1e-9
    print("math_44 OK")


if __name__ == "__main__":
    main()
