"""AE-module: rotate_right -- List rotated right by k positions."""
from __future__ import annotations
VERSION = "ae_26.v1"
def rotate_right(xs: list, k: int) -> list:
    if not xs:
        return []
    k %= len(xs)
    return xs[:] if k == 0 else xs[-k:] + xs[:-k]

def main() -> None:
    assert rotate_right([1, 2, 3], 1) == [3, 1, 2]
    assert rotate_right([1, 2, 3], 3) == [1, 2, 3]
    assert rotate_right([1, 2], 0) == [1, 2]
    print("ae_26 rotate_right OK")
if __name__ == "__main__": main()
