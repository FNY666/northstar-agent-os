"""AD-module: gcd2 -- Greatest common divisor via Euclid."""
from __future__ import annotations
VERSION = "ad_46.v1"
def gcd2(a: int, b: int) -> int:
    while b: a, b = b, a % b
    return abs(a)

def main() -> None:
    assert gcd2(12, 18) == 6
    assert gcd2(7, 5) == 1
    assert gcd2(0, 5) == 5
    print("ad_46 gcd2 OK")
if __name__ == "__main__": main()
