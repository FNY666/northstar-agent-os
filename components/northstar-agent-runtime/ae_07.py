"""AE-module: lcm -- Least common multiple of a and b."""
from __future__ import annotations
import math
VERSION = "ae_07.v1"
def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a * b) // math.gcd(a, b)

def main() -> None:
    assert lcm(4, 6) == 12
    assert lcm(7, 5) == 35
    assert lcm(0, 5) == 0
    print("ae_07 lcm OK")
if __name__ == "__main__": main()
