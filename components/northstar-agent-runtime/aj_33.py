"""AJ-33: Top-k."""
from __future__ import annotations
VERSION = "aj_33.v1"


import heapq
def topk(seq, k):
    return heapq.nlargest(k, seq)

def main() -> None:
    assert topk([3,1,4,1,5],2) == [5,4]
    assert topk([2,1],5) == [2,1]
    print(f"aj_33 OK")
if __name__ == "__main__": main()
