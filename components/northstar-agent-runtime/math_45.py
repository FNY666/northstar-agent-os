"""Dominant eigenpair via power iteration (Rayleigh quotient)."""

from __future__ import annotations

import math
import random


def power_iteration(A, iters: int = 1000, seed: int = 0):
    """Returns (eigenvalue, eigenvector) for the dominant eigenpair."""
    n = len(A)
    if n == 0 or any(len(row) != n for row in A):
        raise ValueError("A must be a non-empty square matrix")
    rng = random.Random(seed)
    v = [rng.random() for _ in range(n)]
    norm = math.sqrt(sum(x * x for x in v)) or 1.0
    v = [x / norm for x in v]
    for _ in range(iters):
        w = [sum(A[i][j] * v[j] for j in range(n)) for i in range(n)]
        norm = math.sqrt(sum(x * x for x in w))
        if norm == 0:
            raise ValueError("iteration collapsed to zero vector")
        v = [x / norm for x in w]
    Av = [sum(A[i][j] * v[j] for j in range(n)) for i in range(n)]
    lam = sum(v[i] * Av[i] for i in range(n))
    return lam, v


def main() -> None:
    lam, v = power_iteration([[2, 0], [0, 1]])
    assert abs(lam - 2.0) < 1e-6
    assert abs(abs(v[0]) - 1.0) < 1e-6
    lam, _ = power_iteration([[4, 1], [2, 3]])
    assert abs(lam - 5.0) < 1e-4  # eigenvalues are 5 and 2
    print("math_45 OK")


if __name__ == "__main__":
    main()
