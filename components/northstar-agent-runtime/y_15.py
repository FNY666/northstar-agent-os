"""Y-module: list_max -- Max of a non-empty list."""
from __future__ import annotations
VERSION = "y_15.v1"
def list_max(xs: list) -> float:
    m = xs[0]
    for x in xs[1:]:
        if x > m: m = x
    return m

def main() -> None:
    assert list_max([3, 1, 9, 2]) == 9
    assert list_max([-5]) == -5
    print("y_15 list_max OK")
if __name__ == "__main__": main()
