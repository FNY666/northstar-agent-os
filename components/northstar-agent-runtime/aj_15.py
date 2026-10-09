"""AJ-15: LCM."""
from __future__ import annotations
VERSION = "aj_15.v1"


import math
def lcm(a, b):
    return abs(a*b) // math.gcd(a, b)

def main() -> None:
    assert lcm(4,6) == 12
    assert lcm(7,5) == 35
    print(f"aj_15 OK")
if __name__ == "__main__": main()
