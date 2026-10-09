"""AD-module: increment -- Add one to an integer."""
from __future__ import annotations
VERSION = "ad_13.v1"
def increment(n: int) -> int:
    return n + 1

def main() -> None:
    assert increment(1) == 2
    assert increment(0) == 1
    assert increment(-1) == 0
    print("ad_13 increment OK")
if __name__ == "__main__": main()
