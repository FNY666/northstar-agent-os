"""Base conversion (2..36) and Roman numerals."""

from __future__ import annotations

_DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def to_base(n: int, base: int) -> str:
    if not 2 <= base <= 36:
        raise ValueError("base must be in [2, 36]")
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)
    out = []
    while n:
        out.append(_DIGITS[n % base])
        n //= base
    return sign + "".join(reversed(out))


def from_base(s: str, base: int) -> int:
    if not 2 <= base <= 36:
        raise ValueError("base must be in [2, 36]")
    s = s.strip().upper()
    if not s:
        raise ValueError("empty string")
    sign = 1
    if s[0] == "-":
        sign = -1
        s = s[1:]
    valid = _DIGITS[:base]
    total = 0
    for ch in s:
        if ch not in valid:
            raise ValueError(f"invalid digit {ch!r} for base {base}")
        total = total * base + valid.index(ch)
    return sign * total


_ROMAN = [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
          (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
          (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")]


def int_to_roman(n: int) -> str:
    if not 1 <= n <= 3999:
        raise ValueError("n must be in [1, 3999]")
    out = []
    for value, numeral in _ROMAN:
        while n >= value:
            out.append(numeral)
            n -= value
    return "".join(out)


def roman_to_int(s: str) -> int:
    s = s.strip().upper()
    if not s:
        raise ValueError("empty string")
    table = {"I": 1, "V": 5, "X": 10, "L": 50,
             "C": 100, "D": 500, "M": 1000}
    total, prev = 0, 0
    for ch in reversed(s):
        if ch not in table:
            raise ValueError(f"invalid numeral {ch!r}")
        v = table[ch]
        if v < prev:
            total -= v
        else:
            total += v
        prev = v
    return total


def main() -> None:
    assert to_base(255, 16) == "FF"
    assert to_base(-10, 2) == "-1010"
    assert to_base(0, 8) == "0"
    assert from_base("FF", 16) == 255
    assert from_base("-1010", 2) == -10
    assert int_to_roman(2026) == "MMXXVI"
    assert int_to_roman(4) == "IV"
    assert roman_to_int("MMXXVI") == 2026
    assert roman_to_int("IV") == 4
    print("math_47 OK")


if __name__ == "__main__":
    main()
