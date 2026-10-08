"""Chinese Remainder Theorem (general form).

crt(remainders, moduli) -> (x, M): smallest x >= 0 solving the system
modulo M = lcm of moduli. Raises ValueError if inconsistent.
"""

from __future__ import annotations


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def crt(remainders, moduli) -> tuple[int, int]:
    remainders = list(remainders)
    moduli = list(moduli)
    if len(remainders) != len(moduli) or not remainders:
        raise ValueError("need non-empty equal-length inputs")
    if any(mm <= 0 for mm in moduli):
        raise ValueError("moduli must be positive")
    x = remainders[0] % moduli[0]
    M = moduli[0]
    for r, mm in zip(remainders[1:], moduli[1:]):
        g, s, _ = _egcd(M, mm)
        if (r - x) % g != 0:
            raise ValueError("inconsistent system")
        step = mm // g
        x = (x + M * (((r - x) // g * s) % step)) % (M // g * mm)
        M = M // g * mm
    return x, M


def main() -> None:
    x, M = crt([2, 3], [3, 5])
    assert (x, M) == (8, 15)
    x, M = crt([2, 3, 2], [3, 5, 7])
    assert x % 3 == 2 and x % 5 == 3 and x % 7 == 2 and M == 105
    x, M = crt([2, 4], [4, 6])  # non-coprime, consistent
    assert (x, M) == (10, 12)
    print("math_27 OK")


if __name__ == "__main__":
    main()
