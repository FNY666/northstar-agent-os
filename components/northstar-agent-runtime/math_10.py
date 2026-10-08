"""Discrete Fourier transform utilities.

dft: naive O(n^2) DFT (any length).
idft: naive inverse DFT.
fft: recursive Cooley-Tukey (length must be a power of 2).
"""

from __future__ import annotations

import cmath
import math


def dft(x):
    """Naive DFT."""
    x = list(x)
    n = len(x)
    if n == 0:
        raise ValueError("empty input")
    return [
        sum(v * cmath.exp(-2j * math.pi * k * t / n) for t, v in enumerate(x))
        for k in range(n)
    ]


def idft(X):
    """Naive inverse DFT."""
    X = list(X)
    n = len(X)
    if n == 0:
        raise ValueError("empty input")
    vals = [
        sum(v * cmath.exp(2j * math.pi * k * t / n) for t, v in enumerate(X))
        / n
        for k in range(n)
    ]
    return [v.real if abs(v.imag) < 1e-9 else v for v in vals]


def is_pow2(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def fft(x):
    """Cooley-Tukey FFT; len(x) must be a power of 2."""
    x = list(x)
    n = len(x)
    if not is_pow2(n):
        raise ValueError("length must be a power of 2")
    if n == 1:
        return [complex(x[0])]
    even = fft(x[0::2])
    odd = fft(x[1::2])
    out = [0j] * n
    for k in range(n // 2):
        tw = cmath.exp(-2j * math.pi * k / n) * odd[k]
        out[k] = even[k] + tw
        out[k + n // 2] = even[k] - tw
    return out


def main() -> None:
    X = fft([1, 0, 0, 0])
    assert all(abs(v - 1) < 1e-9 for v in X)
    # fft matches naive dft
    x = [1, 2, 3, 4, 5, 6, 7, 8]
    f, d = fft(x), dft(x)
    assert all(abs(a - b) < 1e-9 for a, b in zip(f, d))
    # round-trip
    back = idft(dft([1.0, 2.0, 3.0]))
    assert all(abs(a - b) < 1e-9 for a, b in zip(back, [1.0, 2.0, 3.0]))
    print("math_10 OK")


if __name__ == "__main__":
    main()
