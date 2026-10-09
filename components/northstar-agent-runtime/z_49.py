"""z_49: top_k."""
from __future__ import annotations
VERSION = "z_49.v1"
def top_k(xs,k):
    import heapq
    return heapq.nlargest(k,xs)

def main() -> None:
    assert top_k([5,1,3,9],2)==[9,5]
    assert top_k([2,2,1],3)==[2,2,1]
    print('z_49 top_k OK')

if __name__ == "__main__": main()
