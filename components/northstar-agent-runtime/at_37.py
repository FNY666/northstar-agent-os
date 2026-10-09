"""at_37: lerp -- Linear interpolation."""
from __future__ import annotations
VERSION = "at_37.v1"
def lerp(a, b, t):
    return a + (b - a) * t

def main() -> None:
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(0, 10, 0) == 0
    print("at_37 lerp OK")
if __name__ == "__main__": main()
