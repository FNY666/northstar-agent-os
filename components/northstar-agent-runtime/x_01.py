"""X-module: clamp -- Clamp a number into [lo, hi]."""
from __future__ import annotations
VERSION = "x_01.v1"
def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def main() -> None:
    assert clamp(5, 0, 10) == 5
    assert clamp(-3, 0, 10) == 0
    assert clamp(99, 0, 10) == 10
    print("x_01 clamp OK")
if __name__ == "__main__": main()
