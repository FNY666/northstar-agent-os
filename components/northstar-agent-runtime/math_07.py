"""Basic matrix operations on nested lists.

matmul: matrix product with dimension validation.
matvec: matrix-vector product.
transpose, identity: helpers.
"""

from __future__ import annotations


def _check_matrix(M, name="matrix") -> tuple[int, int]:
    if not M or not isinstance(M, (list, tuple)):
        raise ValueError(f"{name} must be a non-empty list of rows")
    cols = len(M[0])
    if cols == 0:
        raise ValueError(f"{name} rows must be non-empty")
    for row in M:
        if len(row) != cols:
            raise ValueError(f"{name} is not rectangular")
    return len(M), cols


def matmul(A, B):
    """Matrix product A @ B."""
    ra, ca = _check_matrix(A, "A")
    rb, cb = _check_matrix(B, "B")
    if ca != rb:
        raise ValueError(f"dimension mismatch: A is {ra}x{ca}, B is {rb}x{cb}")
    return [
        [sum(A[i][k] * B[k][j] for k in range(ca)) for j in range(cb)]
        for i in range(ra)
    ]


def matvec(A, v):
    """Matrix-vector product."""
    r, c = _check_matrix(A, "A")
    if len(v) != c:
        raise ValueError("dimension mismatch")
    return [sum(A[i][k] * v[k] for k in range(c)) for i in range(r)]


def transpose(M):
    """Transpose of M."""
    r, c = _check_matrix(M)
    return [[M[i][j] for i in range(r)] for j in range(c)]


def identity(n: int):
    """n x n identity matrix."""
    if n < 1:
        raise ValueError("n must be >= 1")
    return [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]


def main() -> None:
    A = [[1, 2], [3, 4]]
    B = [[5, 6], [7, 8]]
    assert matmul(A, B) == [[19, 22], [43, 50]]
    assert matvec(A, [1, 1]) == [3, 7]
    assert transpose(A) == [[1, 3], [2, 4]]
    assert matmul(A, identity(2)) == [[1.0, 2.0], [3.0, 4.0]]
    print("math_07 OK")


if __name__ == "__main__":
    main()
