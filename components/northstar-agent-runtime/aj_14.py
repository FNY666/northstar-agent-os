"""AJ-14: GCD of list."""
from __future__ import annotations
VERSION = "aj_14.v1"


import math, functools
def gcd_list(xs):
    return functools.reduce(math.gcd, xs)

def main() -> None:
    assert gcd_list([12,18,24]) == 6
    assert gcd_list([7]) == 7
    print(f"aj_14 OK")
if __name__ == "__main__": main()
