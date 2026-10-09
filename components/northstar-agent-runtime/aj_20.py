"""AJ-20: Binomial coefficient."""
from __future__ import annotations
VERSION = "aj_20.v1"


import math
def ncr(n, r):
    return math.comb(n, r)

def main() -> None:
    assert ncr(5,2) == 10
    assert ncr(10,0) == 1
    print(f"aj_20 OK")
if __name__ == "__main__": main()
