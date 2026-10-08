"""1D signal helpers: moving average, convolution, correlation."""

from __future__ import annotations


def moving_average(xs, window: int):
    xs = list(xs)
    if window < 1:
        raise ValueError("window must be >= 1")
    if window > len(xs):
        raise ValueError("window larger than signal")
    return [sum(xs[i : i + window]) / window for i in range(len(xs) - window + 1)]


def convolve(a, b):
    """Full discrete convolution."""
    a, b = list(a), list(b)
    if not a or not b:
        raise ValueError("empty input")
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return out


def cross_correlate(a, b):
    """Cross-correlation of a and b (full)."""
    return convolve(a, list(reversed(b)))


def main() -> None:
    assert moving_average([1, 2, 3, 4, 5], 3) == [2.0, 3.0, 4.0]
    assert convolve([1, 2, 3], [0, 1, 0.5]) == [0, 1, 2.5, 4.0, 1.5]
    assert convolve([1, 1], [1, 1]) == [1, 2, 1]
    cc = cross_correlate([1, 2, 3], [1, 2, 3])
    assert cc == [3, 8, 14, 8, 3]
    print("math_43 OK")


if __name__ == "__main__":
    main()
