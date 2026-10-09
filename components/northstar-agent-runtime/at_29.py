"""at_29: rotate -- Rotate list left by k."""
from __future__ import annotations
VERSION = "at_29.v1"
def rotate(xs, k):
    k %= len(xs) if xs else 1
    return xs[k:] + xs[:k]

def main() -> None:
    assert rotate([1, 2, 3], 1) == [2, 3, 1]
    assert rotate([], 5) == []
    print("at_29 rotate OK")
if __name__ == "__main__": main()
