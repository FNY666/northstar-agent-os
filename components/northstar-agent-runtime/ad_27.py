"""AD-module: list_product -- Multiply all numbers in a list."""
from __future__ import annotations
VERSION = "ad_27.v1"
def list_product(xs: list) -> float:
    total = 1
    for x in xs: total *= x
    return total

def main() -> None:
    assert list_product([2,3,4]) == 24
    assert list_product([]) == 1
    assert list_product([5,0]) == 0
    print("ad_27 list_product OK")
if __name__ == "__main__": main()
