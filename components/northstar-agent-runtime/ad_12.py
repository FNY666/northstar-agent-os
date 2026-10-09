"""AD-module: negate -- Negate a number."""
from __future__ import annotations
VERSION = "ad_12.v1"
def negate(x: float) -> float:
    return -x

def main() -> None:
    assert negate(5) == -5
    assert negate(-2) == 2
    assert negate(0) == 0
    print("ad_12 negate OK")
if __name__ == "__main__": main()
