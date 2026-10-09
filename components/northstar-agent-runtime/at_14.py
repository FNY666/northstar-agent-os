"""at_14: gcd -- Greatest common divisor."""
from __future__ import annotations
VERSION = "at_14.v1"
def gcd(a, b):
    while b: a, b = b, a % b
    return abs(a)

def main() -> None:
    assert gcd(12, 8) == 4
    assert gcd(7, 5) == 1
    print("at_14 gcd OK")
if __name__ == "__main__": main()
