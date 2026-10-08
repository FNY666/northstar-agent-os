"""Fibonacci numbers via fast doubling (O(log n)).

fib(n), fib_mod(n, m), fib_pair(n) -> (F(n), F(n+1)).
"""

from __future__ import annotations


def fib_pair(n: int) -> tuple[int, int]:
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return (0, 1)
    a, b = fib_pair(n >> 1)
    c = a * ((b << 1) - a)
    d = a * a + b * b
    if n & 1:
        return (d, c + d)
    return (c, d)


def fib(n: int) -> int:
    return fib_pair(n)[0]


def fib_mod(n: int, mod: int) -> int:
    if mod <= 0:
        raise ValueError("mod must be positive")
    if n < 0:
        raise ValueError("n must be non-negative")
    # fast doubling with modular reduction
    def rec(k):
        if k == 0:
            return (0, 1)
        a, b = rec(k >> 1)
        c = (a * ((2 * b - a) % mod)) % mod
        d = (a * a + b * b) % mod
        if k & 1:
            return (d, (c + d) % mod)
        return (c, d)
    return rec(n)[0]


def main() -> None:
    assert [fib(i) for i in range(10)] == [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
    assert fib(100) == 354224848179261915075
    assert fib_mod(10, 1000) == 55
    assert fib_mod(1000, 10**9 + 7) == fib(1000) % (10**9 + 7)
    print("math_28 OK")


if __name__ == "__main__":
    main()
