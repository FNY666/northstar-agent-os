"""AE-module: lerp -- Linear interpolation between a and b at t."""
from __future__ import annotations
VERSION = "ae_36.v1"
def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t

def main() -> None:
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(0, 10, 0) == 0.0
    assert lerp(5, 5, 0.7) == 5.0
    print("ae_36 lerp OK")
if __name__ == "__main__": main()
