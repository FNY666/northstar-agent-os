"""AE-module: gcd -- Greatest common divisor of a and b."""
from __future__ import annotations
import math
VERSION = "ae_06.v1"
def gcd(a: int, b: int) -> int:
    return math.gcd(a, b)

def main() -> None:
    assert gcd(12, 18) == 6
    assert gcd(7, 5) == 1
    assert gcd(0, 9) == 9
    print("ae_06 gcd OK")
if __name__ == "__main__": main()
