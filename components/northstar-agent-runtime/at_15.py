"""at_15: lcm -- Least common multiple."""
from __future__ import annotations
VERSION = "at_15.v1"
def _gcd(a, b):
    while b: a, b = b, a % b
    return a
def lcm(a, b):
    return abs(a * b) // _gcd(a, b) if a and b else 0

def main() -> None:
    assert lcm(4, 6) == 12
    assert lcm(0, 5) == 0
    print("at_15 lcm OK")
if __name__ == "__main__": main()
