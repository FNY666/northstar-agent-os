"""Y-module: abs_diff -- Absolute difference."""
from __future__ import annotations
VERSION = "y_28.v1"
def abs_diff(a: float, b: float) -> float:
    return abs(a - b)

def main() -> None:
    assert abs_diff(5, 2) == 3
    assert abs_diff(2, 5) == 3
    print("y_28 abs_diff OK")
if __name__ == "__main__": main()
