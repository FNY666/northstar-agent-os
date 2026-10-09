"""AD-module: is_prime_small -- Trial-division primality for small ints."""
from __future__ import annotations
VERSION = "ad_50.v1"
def is_prime_small(n: int) -> bool:
    if n < 2: return False
    i = 2
    while i * i <= n:
        if n % i == 0: return False
        i += 1
    return True

def main() -> None:
    assert is_prime_small(2) is True
    assert is_prime_small(15) is False
    assert is_prime_small(1) is False
    print("ad_50 is_prime_small OK")
if __name__ == "__main__": main()
