"""AE-module: interleave -- Alternate elements of two lists."""
from __future__ import annotations
VERSION = "ae_48.v1"
def interleave(a: list, b: list) -> list:
    out = []
    for x, y in zip(a, b):
        out += [x, y]
    return out

def main() -> None:
    assert interleave([1, 2], [3, 4]) == [1, 3, 2, 4]
    assert interleave([], []) == []
    assert interleave([1], [2]) == [1, 2]
    print("ae_48 interleave OK")
if __name__ == "__main__": main()
