"""z_05: rotate_left."""
from __future__ import annotations
VERSION = "z_05.v1"
def rotate_left(xs, k):
    if not xs: return xs
    k %= len(xs); return xs[k:] + xs[:k]

def main() -> None:
    assert rotate_left([1,2,3,4],1) == [2,3,4,1]
    assert rotate_left([1,2],5) == [2,1]
    print('z_05 rotate_left OK')

if __name__ == "__main__": main()
