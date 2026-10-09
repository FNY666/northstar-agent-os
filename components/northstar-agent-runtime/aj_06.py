"""AJ-06: Sliding windows."""
from __future__ import annotations
VERSION = "aj_06.v1"


def windows(seq, n):
    return [seq[i:i+n] for i in range(len(seq)-n+1)]

def main() -> None:
    assert windows([1,2,3,4],2) == [[1,2],[2,3],[3,4]]
    assert windows([1],2) == []
    print(f"aj_06 OK")
if __name__ == "__main__": main()
