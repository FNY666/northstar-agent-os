"""Eigenvalues of a 2x2 matrix (exact via characteristic polynomial).

Returns real floats when the discriminant is non-negative,
complex otherwise. Real pairs are sorted descending.
"""

from __future__ import annotations

import cmath


def eigenvalues_2x2(a, b, c, d):
    """Eigenvalues of [[a, b], [c, d]]."""
    tr = a + d
    dt = a * d - b * c
    disc = tr * tr - 4 * dt
    root = cmath.sqrt(disc)
    l1 = (tr + root) / 2
    l2 = (tr - root) / 2

    def clean(z):
        return z.real if abs(z.imag) < 1e-9 else z

    l1, l2 = clean(l1), clean(l2)
    if isinstance(l1, float) and isinstance(l2, float):
        return (max(l1, l2), min(l1, l2))
    return (l1, l2)


def trace_2x2(a, b, c, d):
    return a + d


def main() -> None:
    l1, l2 = eigenvalues_2x2(2, 0, 0, 3)
    assert (l1, l2) == (3.0, 2.0)
    l1, l2 = eigenvalues_2x2(0, -1, 1, 0)
    assert abs(l1 - 1j) < 1e-9 and abs(l2 + 1j) < 1e-9
    # eigenvalues sum to trace, product to determinant
    l1, l2 = eigenvalues_2x2(4, 1, 2, 3)
    assert abs((l1 + l2) - 7.0) < 1e-9
    assert abs((l1 * l2) - 10.0) < 1e-9
    print("math_09 OK")


if __name__ == "__main__":
    main()
