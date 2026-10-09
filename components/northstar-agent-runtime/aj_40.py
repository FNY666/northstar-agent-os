"""AJ-40: Dot product."""
from __future__ import annotations
VERSION = "aj_40.v1"


def dot(a, b):
    return sum(x*y for x, y in zip(a, b))

def main() -> None:
    assert dot([1,2,3],[4,5,6]) == 32
    assert dot([],[]) == 0
    print(f"aj_40 OK")
if __name__ == "__main__": main()
