"""AF-module: rle_decode -- Expand (value, count) pairs back into a list."""
from __future__ import annotations
VERSION = "af_33"
def rle_decode(pairs: list) -> list:
    out: list = []
    for v, c in pairs:
        out.extend([v] * c)
    return out

def main() -> None:
    assert rle_decode([(1, 2), (2, 3)]) == [1, 1, 2, 2, 2]
    assert rle_decode([]) == []
    assert rle_decode([('a', 0)]) == []
    print("af_33 rle_decode OK")
if __name__ == "__main__": main()
