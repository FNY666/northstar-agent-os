"""Y-module: gcd2 -- GCD of two ints."""
from __future__ import annotations
VERSION = "y_08.v1"
def gcd2(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)

def main() -> None:
    assert gcd2(12, 18) == 6
    assert gcd2(7, 13) == 1
    print("y_08 gcd2 OK")
if __name__ == "__main__": main()
