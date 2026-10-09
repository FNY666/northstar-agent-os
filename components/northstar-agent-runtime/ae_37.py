"""AE-module: dist_2d -- Euclidean distance between two 2D points."""
from __future__ import annotations
import math
VERSION = "ae_37.v1"
def dist_2d(a: list, b: list) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])

def main() -> None:
    assert dist_2d([0, 0], [3, 4]) == 5.0
    assert dist_2d([1, 1], [1, 1]) == 0.0
    assert dist_2d([0, 0], [1, 0]) == 1.0
    print("ae_37 dist_2d OK")
if __name__ == "__main__": main()
