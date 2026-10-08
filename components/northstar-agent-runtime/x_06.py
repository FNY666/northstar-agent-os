"""X-module: is_prime -- Simple primality test."""
from __future__ import annotations
VERSION = "x_06.v1"
def is_prime(n: int) -> bool:
    if n < 2: return False
    if n % 2 == 0: return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0: return False
        i += 2
    return True

def main() -> None:
    assert is_prime(2) and is_prime(13)
    assert not is_prime(1) and not is_prime(15)
    print("x_06 is_prime OK")
if __name__ == "__main__": main()
