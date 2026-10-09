"""AD-module: sign -- Return the sign of a number: -1, 0, or 1."""
from __future__ import annotations
VERSION = "ad_03.v1"
def sign(x: float) -> int:
    return (x > 0) - (x < 0)

def main() -> None:
    assert sign(5) == 1
    assert sign(-2) == -1
    assert sign(0) == 0
    print("ad_03 sign OK")
if __name__ == "__main__": main()
