"""AD-module: head -- Return the first n items of a list."""
from __future__ import annotations
VERSION = "ad_23.v1"
def head(xs: list, n: int) -> list:
    return xs[:n]

def main() -> None:
    assert head([1,2,3], 2) == [1,2]
    assert head([], 5) == []
    assert head([1], 0) == []
    print("ad_23 head OK")
if __name__ == "__main__": main()
