"""AD-module: list_sum -- Sum all numbers in a list."""
from __future__ import annotations
VERSION = "ad_26.v1"
def list_sum(xs: list) -> float:
    total = 0
    for x in xs: total += x
    return total

def main() -> None:
    assert list_sum([1,2,3]) == 6
    assert list_sum([]) == 0
    assert list_sum([-1,1]) == 0
    print("ad_26 list_sum OK")
if __name__ == "__main__": main()
