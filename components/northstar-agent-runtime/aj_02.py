"""AJ-02: Chunk splitter."""
from __future__ import annotations
VERSION = "aj_02.v1"


def chunks(seq, n):
    return [seq[i:i+n] for i in range(0, len(seq), n)]

def main() -> None:
    assert chunks([1,2,3,4,5],2) == [[1,2],[3,4],[5]]
    assert chunks([],3) == []
    print(f"aj_02 OK")
if __name__ == "__main__": main()
