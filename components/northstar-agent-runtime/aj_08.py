"""AJ-08: Run-length encode."""
from __future__ import annotations
VERSION = "aj_08.v1"


def rle_encode(seq):
    if not seq: return []
    out, cur, n = [], seq[0], 1
    for x in seq[1:]:
        if x == cur: n += 1
        else: out.append((cur, n)); cur, n = x, 1
    return out + [(cur, n)]

def main() -> None:
    assert rle_encode('aaabbc') == [('a',3),('b',2),('c',1)]
    assert rle_encode([]) == []
    print(f"aj_08 OK")
if __name__ == "__main__": main()
