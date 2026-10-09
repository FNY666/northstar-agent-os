"""AD-module: double -- Double a number."""
from __future__ import annotations
VERSION = "ad_08.v1"
def double(x: float) -> float:
    return x * 2

def main() -> None:
    assert double(3) == 6
    assert double(-2) == -4
    assert double(0) == 0
    print("ad_08 double OK")
if __name__ == "__main__": main()
