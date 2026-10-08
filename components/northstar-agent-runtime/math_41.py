"""Second-order statistics: covariance, correlation, z-scores."""

from __future__ import annotations

import math


def _mean(xs) -> float:
    xs = list(xs)
    if not xs:
        raise ValueError("empty input")
    return sum(xs) / len(xs)


def covariance(xs, ys) -> float:
    """Population covariance."""
    xs, ys = list(xs), list(ys)
    if len(xs) != len(ys) or not xs:
        raise ValueError("need non-empty equal-length inputs")
    mx, my = _mean(xs), _mean(ys)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / len(xs)


def correlation(xs, ys) -> float:
    """Pearson correlation in [-1, 1]."""
    xs, ys = list(xs), list(ys)
    mx, my = _mean(xs), _mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        raise ValueError("constant input")
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / math.sqrt(sxx * syy)


def zscores(xs):
    """Standardize to zero mean / unit population stdev."""
    xs = list(xs)
    mu = _mean(xs)
    var = sum((x - mu) ** 2 for x in xs) / len(xs)
    if var == 0:
        raise ValueError("constant input")
    sd = math.sqrt(var)
    return [(x - mu) / sd for x in xs]


def weighted_mean(xs, ws) -> float:
    xs, ws = list(xs), list(ws)
    if len(xs) != len(ws) or not xs:
        raise ValueError("need non-empty equal-length inputs")
    total_w = sum(ws)
    if total_w == 0:
        raise ValueError("weights sum to zero")
    return sum(x * w for x, w in zip(xs, ws)) / total_w


def main() -> None:
    assert abs(covariance([1, 2, 3], [1, 2, 3]) - 2 / 3) < 1e-9
    assert abs(correlation([1, 2, 3], [2, 4, 6]) - 1.0) < 1e-9
    assert abs(correlation([1, 2, 3], [6, 4, 2]) + 1.0) < 1e-9
    zs = zscores([1, 2, 3])
    assert abs(sum(zs)) < 1e-9
    assert abs(weighted_mean([1, 2, 3], [1, 1, 2]) - 2.25) < 1e-9
    print("math_41 OK")


if __name__ == "__main__":
    main()
