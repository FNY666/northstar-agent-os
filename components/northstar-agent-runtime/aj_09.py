"""AJ-09: Run-length decode."""
from __future__ import annotations
VERSION = "aj_09.v1"


def rle_decode(pairs):
    return [x for x, n in pairs for _ in range(n)]

def main() -> None:
    assert rle_decode([('a',3),('b',1)]) == ['a','a','a','b']
    assert rle_decode([]) == []
    print(f"aj_09 OK")
if __name__ == "__main__": main()
