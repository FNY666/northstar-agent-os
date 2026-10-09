"""AJ-34: Bisect index."""
from __future__ import annotations
VERSION = "aj_34.v1"


import bisect
def sorted_index(sorted_seq, x):
    return bisect.bisect_left(sorted_seq, x)

def main() -> None:
    assert sorted_index([1,3,5],4) == 2
    assert sorted_index([1,3,5],3) == 1
    print(f"aj_34 OK")
if __name__ == "__main__": main()
