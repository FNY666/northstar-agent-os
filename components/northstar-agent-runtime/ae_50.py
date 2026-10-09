"""AE-module: range_sum -- Sum of xs[lo:hi]."""
from __future__ import annotations
VERSION = "ae_50.v1"
def range_sum(xs: list, lo: int, hi: int):
    return sum(xs[lo:hi])

def main() -> None:
    assert range_sum([1, 2, 3, 4], 1, 3) == 5
    assert range_sum([], 0, 0) == 0
    assert range_sum([5], 0, 1) == 5
    print("ae_50 range_sum OK")
if __name__ == "__main__": main()
