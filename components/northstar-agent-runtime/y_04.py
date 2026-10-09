"""Y-module: median3 -- Median of three numbers."""
from __future__ import annotations
VERSION = "y_04.v1"
def median3(a: float, b: float, c: float) -> float:
    return sorted((a, b, c))[1]

def main() -> None:
    assert median3(1, 3, 2) == 2
    assert median3(9, 1, 5) == 5
    print("y_04 median3 OK")
if __name__ == "__main__": main()
