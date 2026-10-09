"""AD-module: list_max -- Maximum of a non-empty list."""
from __future__ import annotations
VERSION = "ad_29.v1"
def list_max(xs: list) -> float:
    m = xs[0]
    for x in xs[1:]:
        if x > m: m = x
    return m

def main() -> None:
    assert list_max([3,1,2]) == 3
    assert list_max([7]) == 7
    assert list_max([-1,-5,-2]) == -1
    print("ad_29 list_max OK")
if __name__ == "__main__": main()
