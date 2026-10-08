"""X-module: rotate_left -- Rotate list left by k."""
from __future__ import annotations
VERSION = "x_18.v1"
def rotate_left(xs: list, k: int) -> list:
    if not xs: return []
    k %= len(xs)
    return xs[k:] + xs[:k]

def main() -> None:
    assert rotate_left([1, 2, 3, 4], 1) == [2, 3, 4, 1]
    assert rotate_left([], 5) == []
    print("x_18 rotate_left OK")
if __name__ == "__main__": main()
