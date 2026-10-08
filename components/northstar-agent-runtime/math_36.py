"""Advanced combinatorics: Catalan, Bell, Stirling2, partitions."""

from __future__ import annotations

import math


def catalan(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    return math.comb(2 * n, n) // (n + 1)


def bell(n: int) -> int:
    """Bell numbers via the Bell triangle."""
    if n < 0:
        raise ValueError("n must be non-negative")
    tri = [[1]]
    for i in range(1, n + 1):
        row = [tri[i - 1][-1]]
        for j in range(1, i + 1):
            row.append(row[j - 1] + tri[i - 1][j - 1])
        tri.append(row)
    return tri[n][0]


def stirling2(n: int, k: int) -> int:
    """Stirling numbers of the second kind."""
    if n < 0 or k < 0:
        raise ValueError("n, k must be non-negative")
    if k > n:
        return 0
    s = [[0] * (k + 1) for _ in range(n + 1)]
    s[0][0] = 1
    for i in range(1, n + 1):
        for j in range(1, min(i, k) + 1):
            s[i][j] = j * s[i - 1][j] + s[i - 1][j - 1]
    return s[n][k]


def partitions(n: int) -> int:
    """Partition count p(n) via coin-change DP."""
    if n < 0:
        raise ValueError("n must be non-negative")
    dp = [0] * (n + 1)
    dp[0] = 1
    for coin in range(1, n + 1):
        for total in range(coin, n + 1):
            dp[total] += dp[total - coin]
    return dp[n]


def main() -> None:
    assert [catalan(i) for i in range(6)] == [1, 1, 2, 5, 14, 42]
    assert [bell(i) for i in range(6)] == [1, 1, 2, 5, 15, 52]
    assert stirling2(4, 2) == 7
    assert stirling2(5, 5) == 1
    assert partitions(5) == 7
    assert partitions(10) == 42
    print("math_36 OK")


if __name__ == "__main__":
    main()
