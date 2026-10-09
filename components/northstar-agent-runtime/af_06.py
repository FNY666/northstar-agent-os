"""AF-module: clamp -- Clamp x into the closed interval [lo, hi]."""
from __future__ import annotations
VERSION = "af_06"
def clamp(x: float, lo: float, hi: float) -> float:
    if lo > hi:
        raise ValueError('lo must be <= hi')
    return max(lo, min(hi, x))

def main() -> None:
    assert clamp(5, 0, 10) == 5
    assert clamp(-3, 0, 10) == 0
    assert clamp(99, 0, 10) == 10
    print("af_06 clamp OK")
if __name__ == "__main__": main()
