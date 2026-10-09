"""Y-module: smoothstep -- Smoothstep easing in [0,1]."""
from __future__ import annotations
VERSION = "y_45.v1"
def smoothstep(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)

def main() -> None:
    assert smoothstep(0.0) == 0.0
    assert smoothstep(1.0) == 1.0
    print("y_45 smoothstep OK")
if __name__ == "__main__": main()
