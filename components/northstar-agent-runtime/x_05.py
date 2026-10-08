"""X-module: gcd -- Greatest common divisor."""
from __future__ import annotations
VERSION = "x_05.v1"
import math
def gcd(a: int, b: int) -> int:
    return math.gcd(a, b)

def main() -> None:
    assert gcd(12, 8) == 4
    assert gcd(7, 5) == 1
    assert gcd(0, 9) == 9
    print("x_05 gcd OK")
if __name__ == "__main__": main()
