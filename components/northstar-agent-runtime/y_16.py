"""Y-module: list_min -- Min of a non-empty list."""
from __future__ import annotations
VERSION = "y_16.v1"
def list_min(xs: list) -> float:
    m = xs[0]
    for x in xs[1:]:
        if x < m: m = x
    return m

def main() -> None:
    assert list_min([3, 1, 9, 2]) == 1
    assert list_min([7]) == 7
    print("y_16 list_min OK")
if __name__ == "__main__": main()
