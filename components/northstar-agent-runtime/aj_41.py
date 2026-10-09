"""AJ-41: Norm L2."""
from __future__ import annotations
VERSION = "aj_41.v1"


import math
def norm(v):
    return math.sqrt(sum(x*x for x in v))

def main() -> None:
    assert abs(norm([3,4]) - 5.0) < 1e-9
    assert norm([0,0]) == 0.0
    print(f"aj_41 OK")
if __name__ == "__main__": main()
