"""Y-module: rotate_left -- Rotate list left by k."""
from __future__ import annotations
VERSION = "y_24.v1"
def rotate_left(xs: list, k: int) -> list:
    if not xs: return []
    k %= len(xs)
    return xs[k:] + xs[:k]

def main() -> None:
    assert rotate_left([1, 2, 3, 4], 1) == [2, 3, 4, 1]
    assert rotate_left([], 5) == []
    print("y_24 rotate_left OK")
if __name__ == "__main__": main()
