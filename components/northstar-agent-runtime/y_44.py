"""Y-module: lerp -- Linear interpolation."""
from __future__ import annotations
VERSION = "y_44.v1"
def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t

def main() -> None:
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(2, 4, 0) == 2.0
    print("y_44 lerp OK")
if __name__ == "__main__": main()
