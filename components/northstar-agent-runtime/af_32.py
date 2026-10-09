"""AF-module: rle_encode -- Run-length encode a list into (value, count) pairs."""
from __future__ import annotations
VERSION = "af_32"
import itertools
def rle_encode(xs: list) -> list:
    return [(k, sum(1 for _ in g)) for k, g in itertools.groupby(xs)]

def main() -> None:
    assert rle_encode([1, 1, 2, 2, 2, 3]) == [(1, 2), (2, 3), (3, 1)]
    assert rle_encode([]) == []
    assert rle_encode('aaabb') == [('a', 3), ('b', 2)]
    print("af_32 rle_encode OK")
if __name__ == "__main__": main()
