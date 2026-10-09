"""Y-module: euclidean2d -- Euclidean distance in 2D."""
from __future__ import annotations
VERSION = "y_40.v1"
def euclidean2d(a: tuple, b: tuple) -> float:
    return ((a[0]-b[0])**2 + (a[1]-b[1])**2) ** 0.5

def main() -> None:
    assert euclidean2d((0, 0), (3, 4)) == 5.0
    assert euclidean2d((1, 1), (1, 1)) == 0.0
    print("y_40 euclidean2d OK")
if __name__ == "__main__": main()
