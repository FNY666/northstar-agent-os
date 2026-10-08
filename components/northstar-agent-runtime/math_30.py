"""Digit manipulation utilities (base 10 unless noted).

digit_sum, digital_root, is_palindrome_number, reverse_number.
"""

from __future__ import annotations


def digit_sum(n: int, base: int = 10) -> int:
    if base < 2:
        raise ValueError("base must be >= 2")
    n = abs(n)
    total = 0
    while n:
        total += n % base
        n //= base
    return total


def digital_root(n: int) -> int:
    n = abs(n)
    while n >= 10:
        n = digit_sum(n)
    return n


def reverse_number(n: int) -> int:
    sign = -1 if n < 0 else 1
    return sign * int(str(abs(n))[::-1] or "0")


def is_palindrome_number(n: int) -> bool:
    s = str(abs(n))
    return s == s[::-1]


def main() -> None:
    assert digit_sum(12345) == 15
    assert digit_sum(0) == 0
    assert digit_sum(255, 16) == 30  # 0xFF -> 15 + 15
    assert digital_root(9875) == 2
    assert reverse_number(12345) == 54321
    assert reverse_number(-120) == -21
    assert is_palindrome_number(12321)
    assert not is_palindrome_number(12345)
    print("math_30 OK")


if __name__ == "__main__":
    main()
