"""Modular square roots via Tonelli-Shanks.

mod_sqrt(n, p): r with r*r = n (mod p) for odd prime p,
or None when n is a non-residue.
"""

from __future__ import annotations


def mod_sqrt(n: int, p: int):
    """Tonelli-Shanks; p must be an odd prime."""
    if p <= 2 or p % 2 == 0:
        raise ValueError("p must be an odd prime")
    n %= p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    mm = s
    while t != 1:
        t2 = (t * t) % p
        i = 1
        while i < mm:
            if t2 == 1:
                break
            t2 = (t2 * t2) % p
            i += 1
        b = pow(c, 1 << (mm - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        mm = i
    return r


def main() -> None:
    r = mod_sqrt(2, 7)
    assert r in (3, 4) and (r * r) % 7 == 2
    assert mod_sqrt(3, 7) is None
    r = mod_sqrt(5, 41)
    assert (r * r) % 41 == 5
    assert mod_sqrt(0, 7) == 0
    print("math_38 OK")


if __name__ == "__main__":
    main()
