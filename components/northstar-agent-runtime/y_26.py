"""Y-module: clamp_int -- Clamp int into [lo, hi]."""
from __future__ import annotations
VERSION = "y_26.v1"
def clamp_int(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))

def main() -> None:
    assert clamp_int(5, 0, 10) == 5
    assert clamp_int(-1, 0, 10) == 0
    print("y_26 clamp_int OK")
if __name__ == "__main__": main()
