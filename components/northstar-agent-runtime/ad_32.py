"""AD-module: count_occ -- Count occurrences of a value in a list."""
from __future__ import annotations
VERSION = "ad_32.v1"
def count_occ(xs: list, v) -> int:
    n = 0
    for x in xs:
        if x == v: n += 1
    return n

def main() -> None:
    assert count_occ([1,2,2,3], 2) == 2
    assert count_occ([], 1) == 0
    assert count_occ([5], 5) == 1
    print("ad_32 count_occ OK")
if __name__ == "__main__": main()
