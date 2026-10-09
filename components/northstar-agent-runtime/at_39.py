"""at_39: is_prime -- True if n is prime."""
from __future__ import annotations
VERSION = "at_39.v1"
def is_prime(n):
    return n > 1 and all(n % i for i in range(2, int(n ** 0.5) + 1))

def main() -> None:
    assert is_prime(7) is True
    assert is_prime(9) is False
    print("at_39 is_prime OK")
if __name__ == "__main__": main()
