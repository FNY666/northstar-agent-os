"""AJ-05: Rotate list."""
from __future__ import annotations
VERSION = "aj_05.v1"


def rotate(seq, k):
    k %= len(seq)
    return seq[k:] + seq[:k]

def main() -> None:
    assert rotate([1,2,3,4],1) == [2,3,4,1]
    assert rotate([1,2,3],5) == [3,1,2]
    print(f"aj_05 OK")
if __name__ == "__main__": main()
