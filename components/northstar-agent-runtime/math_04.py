"""Least common multiple utilities."""

from __future__ import annotations

import math


def lcm(a: int, b: int) -> int:
    """Least common multiple; 0 if either input is 0."""
    if a == 0 or b == 0:
        return 0
    return abs(a // math.gcd(a, b) * b)


def lcm_list(nums) -> int:
    """LCM of an iterable of ints."""
    nums = list(nums)
    if not nums:
        raise ValueError("empty input")
    result = 1
    for x in nums:
        result = lcm(result, x)
    return result


def main() -> None:
    assert lcm(4, 6) == 12
    assert lcm(7, 5) == 35
    assert lcm(0, 5) == 0
    assert lcm(-4, 6) == 12
    assert lcm_list([2, 3, 4]) == 12
    assert lcm_list([5]) == 5
    print("math_04 OK")


if __name__ == "__main__":
    main()
