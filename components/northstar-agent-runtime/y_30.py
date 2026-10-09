"""Y-module: is_prime_small -- Trial-division primality test."""
from __future__ import annotations
VERSION = "y_30.v1"
def is_prime_small(n: int) -> bool:
    if n < 2: return False
    i = 2
    while i * i <= n:
        if n % i == 0: return False
        i += 1
    return True

def main() -> None:
    assert is_prime_small(17) is True
    assert is_prime_small(15) is False
    print("y_30 is_prime_small OK")
if __name__ == "__main__": main()
