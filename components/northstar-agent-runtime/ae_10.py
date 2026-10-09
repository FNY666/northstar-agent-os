"""AE-module: is_prime -- True if n is prime (trial division)."""
from __future__ import annotations
VERSION = "ae_10.v1"
def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True

def main() -> None:
    assert is_prime(2) is True
    assert is_prime(13) is True
    assert is_prime(15) is False
    print("ae_10 is_prime OK")
if __name__ == "__main__": main()
