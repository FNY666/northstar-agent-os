"""at_40: primes_upto -- Primes up to n."""
from __future__ import annotations
VERSION = "at_40.v1"
def primes_upto(n):
    return [i for i in range(2, n + 1) if all(i % j for j in range(2, int(i ** 0.5) + 1))]

def main() -> None:
    assert primes_upto(10) == [2, 3, 5, 7]
    assert primes_upto(1) == []
    print("at_40 primes_upto OK")
if __name__ == "__main__": main()
