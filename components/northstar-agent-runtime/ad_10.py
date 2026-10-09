"""AD-module: square -- Square a number."""
from __future__ import annotations
VERSION = "ad_10.v1"
def square(x: float) -> float:
    return x * x

def main() -> None:
    assert square(3) == 9
    assert square(-4) == 16
    assert square(0) == 0
    print("ad_10 square OK")
if __name__ == "__main__": main()
