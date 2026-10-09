"""Y-module: distinct_prime_factors -- Count distinct prime factors."""
from __future__ import annotations
VERSION = "y_31.v1"
def distinct_prime_factors(n: int) -> int:
    n, f, i = abs(n), set(), 2
    while i * i <= n:
        while n % i == 0: f.add(i); n //= i
        i += 1
    if n > 1: f.add(n)
    return len(f)

def main() -> None:
    assert distinct_prime_factors(12) == 2
    assert distinct_prime_factors(7) == 1
    print("y_31 distinct_prime_factors OK")
if __name__ == "__main__": main()
