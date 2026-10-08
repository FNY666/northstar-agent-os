"""Descriptive statistics.

mean, median, mode (smallest most-frequent), variance (population),
stdev, data_range. Empty input raises ValueError.
"""

from __future__ import annotations

import math
from collections import Counter


def _check(xs, name="data"):
    xs = list(xs)
    if not xs:
        raise ValueError(f"{name} is empty")
    return xs


def mean(xs) -> float:
    xs = _check(xs)
    return sum(xs) / len(xs)


def median(xs) -> float:
    xs = sorted(_check(xs))
    n = len(xs)
    mid = n // 2
    if n % 2:
        return float(xs[mid])
    return (xs[mid - 1] + xs[mid]) / 2.0


def mode(xs):
    """Smallest value among those with maximal frequency."""
    xs = _check(xs)
    counts = Counter(xs)
    top = max(counts.values())
    return min(v for v, c in counts.items() if c == top)


def variance(xs) -> float:
    """Population variance."""
    xs = _check(xs)
    mu = mean(xs)
    return sum((x - mu) ** 2 for x in xs) / len(xs)


def stdev(xs) -> float:
    return math.sqrt(variance(xs))


def data_range(xs) -> float:
    xs = _check(xs)
    return max(xs) - min(xs)


def main() -> None:
    assert mean([1, 2, 3, 4]) == 2.5
    assert median([3, 1, 2]) == 2.0
    assert median([1, 2, 3, 4]) == 2.5
    assert mode([1, 2, 2, 3, 3]) == 2
    assert abs(variance([2, 4, 4, 4, 5, 5, 7, 9]) - 4.0) < 1e-9
    assert abs(stdev([2, 4, 4, 4, 5, 5, 7, 9]) - 2.0) < 1e-9
    assert data_range([1, 5, 3]) == 4
    print("math_11 OK")


if __name__ == "__main__":
    main()
