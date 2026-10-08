"""Univariate polynomials, coefficients lowest-degree first.

peval: Horner evaluation. padd, pmul, pderivative, ptrim.
"""

from __future__ import annotations


def ptrim(p):
    """Drop leading zero coefficients (keep at least one)."""
    p = list(p)
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p


def peval(coeffs, x):
    """Evaluate polynomial at x (Horner)."""
    coeffs = list(coeffs)
    if not coeffs:
        raise ValueError("empty coefficients")
    result = 0
    for c in reversed(coeffs):
        result = result * x + c
    return result


def padd(p, q):
    n = max(len(p), len(q))
    p = list(p) + [0] * (n - len(p))
    q = list(q) + [0] * (n - len(q))
    return ptrim([a + b for a, b in zip(p, q)])


def pmul(p, q):
    p, q = list(p), list(q)
    if not p or not q:
        raise ValueError("empty coefficients")
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            out[i + j] += a * b
    return ptrim(out)


def pderivative(p):
    p = list(p)
    if len(p) <= 1:
        return [0]
    return ptrim([i * c for i, c in enumerate(p)][1:])


def main() -> None:
    # 1 + 2x + 3x^2 at x=2 -> 17
    assert peval([1, 2, 3], 2) == 17
    assert padd([1, 2], [3, 4, 5]) == [4, 6, 5]
    assert pmul([1, 1], [1, 1]) == [1, 2, 1]  # (1+x)^2
    assert pderivative([1, 2, 3]) == [2, 6]
    assert pderivative([5]) == [0]
    print("math_24 OK")


if __name__ == "__main__":
    main()
