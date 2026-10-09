"""AF-module: rotate -- Rotate a list left by k positions (negative rotates right)."""
from __future__ import annotations
VERSION = "af_29"
from collections import deque
def rotate(xs: list, k: int) -> list:
    dq = deque(xs)
    dq.rotate(-k)
    return list(dq)

def main() -> None:
    assert rotate([1, 2, 3, 4], 1) == [2, 3, 4, 1]
    assert rotate([1, 2, 3, 4], -1) == [4, 1, 2, 3]
    assert rotate([], 3) == []
    print("af_29 rotate OK")
if __name__ == "__main__": main()
