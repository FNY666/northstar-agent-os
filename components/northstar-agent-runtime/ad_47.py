"""AD-module: lcm2 -- Least common multiple."""
from __future__ import annotations
VERSION = "ad_47.v1"
def lcm2(a: int, b: int) -> int:
    from math import gcd
    return abs(a * b) // gcd(a, b) if a and b else 0

def main() -> None:
    assert lcm2(4, 6) == 12
    assert lcm2(7, 5) == 35
    assert lcm2(0, 5) == 0
    print("ad_47 lcm2 OK")
if __name__ == "__main__": main()
