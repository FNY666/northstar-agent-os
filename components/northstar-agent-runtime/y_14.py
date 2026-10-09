"""Y-module: digital_root -- Digital root of n."""
from __future__ import annotations
VERSION = "y_14.v1"
def digital_root(n: int) -> int:
    n = abs(n)
    while n >= 10: n = sum(int(d) for d in str(n))
    return n

def main() -> None:
    assert digital_root(38) == 2
    assert digital_root(9) == 9
    print("y_14 digital_root OK")
if __name__ == "__main__": main()
