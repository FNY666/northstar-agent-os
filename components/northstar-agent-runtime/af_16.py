"""AF-module: is_prime -- True if n is a prime number."""
from __future__ import annotations
VERSION = "af_16"
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
    assert is_prime(17) is True
    assert is_prime(15) is False
    assert is_prime(1) is False
    print("af_16 is_prime OK")
if __name__ == "__main__": main()
