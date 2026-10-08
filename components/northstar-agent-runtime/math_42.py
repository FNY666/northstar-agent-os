"""Discrete distribution PMFs and expected values.

binomial_pmf, poisson_pmf, geometric_pmf, expected_value.
"""

from __future__ import annotations

import math


def binomial_pmf(n: int, k: int, p: float) -> float:
    if n < 0 or not 0 <= k <= n:
        raise ValueError("bad n/k")
    if not 0 <= p <= 1:
        raise ValueError("p must be in [0, 1]")
    return math.comb(n, k) * p**k * (1 - p) ** (n - k)


def poisson_pmf(lam: float, k: int) -> float:
    if lam < 0 or k < 0:
        raise ValueError("bad lam/k")
    return math.exp(-lam) * lam**k / math.factorial(k)


def geometric_pmf(p: float, k: int) -> float:
    """P(first success on trial k), k >= 1."""
    if not 0 < p <= 1:
        raise ValueError("p must be in (0, 1]")
    if k < 1:
        raise ValueError("k must be >= 1")
    return p * (1 - p) ** (k - 1)


def expected_value(values, probs) -> float:
    values, probs = list(values), list(probs)
    if len(values) != len(probs) or not values:
        raise ValueError("need non-empty equal-length inputs")
    if any(pr < 0 for pr in probs):
        raise ValueError("probabilities must be non-negative")
    total = sum(probs)
    if total == 0:
        raise ValueError("probabilities sum to zero")
    return sum(v * pr for v, pr in zip(values, probs)) / total


def main() -> None:
    assert abs(binomial_pmf(10, 5, 0.5) - 0.24609375) < 1e-9
    assert abs(poisson_pmf(3.0, 0) - math.exp(-3)) < 1e-12
    assert abs(geometric_pmf(0.5, 1) - 0.5) < 1e-12
    assert abs(expected_value([1, 2, 3], [0.2, 0.3, 0.5]) - 2.3) < 1e-9
    # binomial pmf sums to 1
    assert abs(sum(binomial_pmf(8, k, 0.3) for k in range(9)) - 1.0) < 1e-9
    print("math_42 OK")


if __name__ == "__main__":
    main()
