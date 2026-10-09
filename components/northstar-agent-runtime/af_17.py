"""AF-module: lcm -- Least common multiple of two integers."""
from __future__ import annotations
VERSION = "af_17"
import math
def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a * b) // math.gcd(a, b)

def main() -> None:
    assert lcm(4, 6) == 12
    assert lcm(0, 5) == 0
    assert lcm(7, 5) == 35
    print("af_17 lcm OK")
if __name__ == "__main__": main()
