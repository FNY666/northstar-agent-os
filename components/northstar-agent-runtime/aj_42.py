"""AJ-42: Min-max normalize."""
from __future__ import annotations
VERSION = "aj_42.v1"


def minmax(xs):
    lo, hi = min(xs), max(xs)
    return [(x-lo)/(hi-lo) if hi > lo else 0.0 for x in xs]

def main() -> None:
    assert minmax([1,2,3]) == [0.0,0.5,1.0]
    assert minmax([5,5]) == [0.0,0.0]
    print(f"aj_42 OK")
if __name__ == "__main__": main()
