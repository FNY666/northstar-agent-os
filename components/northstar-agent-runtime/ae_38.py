"""AE-module: tri_area -- Area of a triangle from three 2D points."""
from __future__ import annotations
VERSION = "ae_38.v1"
def tri_area(a: list, b: list, c: list) -> float:
    return abs(a[0] * (b[1] - c[1]) + b[0] * (c[1] - a[1]) + c[0] * (a[1] - b[1])) / 2

def main() -> None:
    assert tri_area([0, 0], [4, 0], [0, 3]) == 6.0
    assert tri_area([0, 0], [1, 1], [2, 2]) == 0.0
    assert tri_area([0, 0], [1, 0], [0, 1]) == 0.5
    print("ae_38 tri_area OK")
if __name__ == "__main__": main()
