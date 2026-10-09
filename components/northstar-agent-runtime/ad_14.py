"""AD-module: decrement -- Subtract one from an integer."""
from __future__ import annotations
VERSION = "ad_14.v1"
def decrement(n: int) -> int:
    return n - 1

def main() -> None:
    assert decrement(1) == 0
    assert decrement(0) == -1
    assert decrement(-5) == -6
    print("ad_14 decrement OK")
if __name__ == "__main__": main()
