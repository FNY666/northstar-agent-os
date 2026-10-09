"""AE-module: pstdev -- Population standard deviation of a non-empty list."""
from __future__ import annotations
import math
VERSION = "ae_33.v1"
def pstdev(xs: list) -> float:
    if not xs:
        raise ValueError('empty')
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))

def main() -> None:
    assert pstdev([2, 4, 4, 4, 5, 5, 7, 9]) == 2.0
    assert pstdev([5, 5, 5]) == 0.0
    assert pstdev([1, 3]) == 1.0
    print("ae_33 pstdev OK")
if __name__ == "__main__": main()
