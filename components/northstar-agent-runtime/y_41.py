"""Y-module: manhattan2d -- Manhattan distance in 2D."""
from __future__ import annotations
VERSION = "y_41.v1"
def manhattan2d(a: tuple, b: tuple) -> float:
    return abs(a[0]-b[0]) + abs(a[1]-b[1])

def main() -> None:
    assert manhattan2d((0, 0), (3, 4)) == 7
    assert manhattan2d((1, 2), (1, 2)) == 0
    print("y_41 manhattan2d OK")
if __name__ == "__main__": main()
