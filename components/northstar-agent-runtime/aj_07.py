"""AJ-07: Interleave."""
from __future__ import annotations
VERSION = "aj_07.v1"


def interleave(a, b):
    out = []
    for x, y in zip(a, b): out += [x, y]
    return out + list(a[len(b):]) + list(b[len(a):])

def main() -> None:
    assert interleave([1,3],[2,4]) == [1,2,3,4]
    assert interleave([1],[2,3,4]) == [1,2,3,4]
    print(f"aj_07 OK")
if __name__ == "__main__": main()
