"""AE-module: cross_2d -- 2D cross product (scalar z-component)."""
from __future__ import annotations
VERSION = "ae_35.v1"
def cross_2d(a: list, b: list) -> float:
    return a[0] * b[1] - a[1] * b[0]

def main() -> None:
    assert cross_2d([1, 0], [0, 1]) == 1
    assert cross_2d([1, 1], [1, 1]) == 0
    assert cross_2d([2, 3], [4, 5]) == -2
    print("ae_35 cross_2d OK")
if __name__ == "__main__": main()
