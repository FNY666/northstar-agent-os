"""Y-module: lcm2 -- LCM of two ints."""
from __future__ import annotations
VERSION = "y_09.v1"
def lcm2(a: int, b: int) -> int:
    g = __import__("math").gcd(a, b)
    return abs(a * b) // g if g else 0

def main() -> None:
    assert lcm2(4, 6) == 12
    assert lcm2(7, 5) == 35
    print("y_09 lcm2 OK")
if __name__ == "__main__": main()
