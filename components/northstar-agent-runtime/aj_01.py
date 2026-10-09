"""AJ-01: Moving average."""
from __future__ import annotations
VERSION = "aj_01.v1"


import collections
def moving_average(seq, n=3):
    q, out = collections.deque(maxlen=n), []
    for x in seq:
        q.append(x); out.append(sum(q) / len(q))
    return out

def main() -> None:
    assert moving_average([1,2,3,4],2) == [1.0,1.5,2.5,3.5]
    assert moving_average([5],3) == [5.0]
    print(f"aj_01 OK")
if __name__ == "__main__": main()
