"""AE-module: rotate_left -- List rotated left by k positions."""
from __future__ import annotations
VERSION = "ae_25.v1"
def rotate_left(xs: list, k: int) -> list:
    if not xs:
        return []
    k %= len(xs)
    return xs[k:] + xs[:k]

def main() -> None:
    assert rotate_left([1, 2, 3], 1) == [2, 3, 1]
    assert rotate_left([1, 2, 3], 3) == [1, 2, 3]
    assert rotate_left([], 2) == []
    print("ae_25 rotate_left OK")
if __name__ == "__main__": main()
