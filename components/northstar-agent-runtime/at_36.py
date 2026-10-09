"""at_36: clamp -- Clamp v into [lo, hi]."""
from __future__ import annotations
VERSION = "at_36.v1"
def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def main() -> None:
    assert clamp(5, 0, 10) == 5
    assert clamp(-1, 0, 10) == 0
    print("at_36 clamp OK")
if __name__ == "__main__": main()
