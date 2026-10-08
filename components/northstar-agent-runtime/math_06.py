"""Fast exponentiation (binary exponentiation).

fast_pow: exact for ints; supports negative exponents via float.
fast_pow_mod: thin wrapper over built-in pow with modulus.
"""

from __future__ import annotations


def fast_pow(base, exp: int):
    """Binary exponentiation. Negative exp returns float."""
    if exp < 0:
        return 1.0 / fast_pow(base, -exp)
    result = 1
    b = base
    e = exp
    while e:
        if e & 1:
            result *= b
        b *= b
        e >>= 1
    return result


def fast_pow_mod(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation (exp >= 0, mod > 0)."""
    if exp < 0:
        raise ValueError("exponent must be non-negative")
    if mod <= 0:
        raise ValueError("modulus must be positive")
    return pow(base, exp, mod)


def main() -> None:
    assert fast_pow(2, 10) == 1024
    assert fast_pow(3, 0) == 1
    assert fast_pow(5, 3) == 125
    assert abs(fast_pow(2, -2) - 0.25) < 1e-12
    assert fast_pow(2, 100) == 2**100
    assert fast_pow_mod(2, 10, 1000) == 24
    print("math_06 OK")


if __name__ == "__main__":
    main()
