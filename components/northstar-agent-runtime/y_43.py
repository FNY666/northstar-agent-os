"""Y-module: cross2d -- 2D cross product (scalar)."""
from __future__ import annotations
VERSION = "y_43.v1"
def cross2d(a: tuple, b: tuple) -> float:
    return a[0]*b[1] - a[1]*b[0]

def main() -> None:
    assert cross2d((1, 0), (0, 1)) == 1
    assert cross2d((2, 2), (1, 1)) == 0
    print("y_43 cross2d OK")
if __name__ == "__main__": main()
