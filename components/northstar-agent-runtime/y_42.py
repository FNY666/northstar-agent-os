"""Y-module: dot2d -- Dot product of 2D vectors."""
from __future__ import annotations
VERSION = "y_42.v1"
def dot2d(a: tuple, b: tuple) -> float:
    return a[0]*b[0] + a[1]*b[1]

def main() -> None:
    assert dot2d((1, 2), (3, 4)) == 11
    assert dot2d((1, 0), (0, 1)) == 0
    print("y_42 dot2d OK")
if __name__ == "__main__": main()
