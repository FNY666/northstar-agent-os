"""AJ-47: KNN nearest."""
from __future__ import annotations
VERSION = "aj_47.v1"


import math
def nearest(points, q):
    return min(points, key=lambda p: math.dist(p, q))

def main() -> None:
    assert nearest([(0,0),(5,5)], (1,1)) == (0,0)
    assert nearest([(3,4)], (0,0)) == (3,4)
    print(f"aj_47 OK")
if __name__ == "__main__": main()
